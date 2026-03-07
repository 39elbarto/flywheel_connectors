//! `Roam Research` API types.

use serde::{Deserialize, Serialize};

/// A `Roam Research` page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page {
    pub uid: String,
    pub title: String,
    #[serde(rename = "create-time")]
    pub create_time: Option<i64>,
    #[serde(rename = "edit-time")]
    pub edit_time: Option<i64>,
    pub children: Option<Vec<serde_json::Value>>,
}

/// A `Roam Research` block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub uid: String,
    pub string: Option<String>,
    pub order: Option<i64>,
    #[serde(rename = "create-time")]
    pub create_time: Option<i64>,
    #[serde(rename = "edit-time")]
    pub edit_time: Option<i64>,
    pub children: Option<Vec<serde_json::Value>>,
    pub open: Option<bool>,
    pub heading: Option<i64>,
}

/// List of pages returned from a Datalog query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageList {
    pub pages: Vec<serde_json::Value>,
}

/// List of blocks returned from a Datalog query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockList {
    pub blocks: Vec<serde_json::Value>,
}

/// Block creation response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockCreateResponse {
    pub uid: String,
}

/// Datalog query request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatalogQuery {
    pub query: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<serde_json::Value>>,
}

/// Write action for creating blocks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteAction {
    pub action: String,
    pub location: WriteLocation,
    pub block: WriteBlock,
}

/// Location for a write operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteLocation {
    #[serde(rename = "parent-uid")]
    pub parent_uid: String,
    pub order: String,
}

/// Block content for a write operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteBlock {
    pub string: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open: Option<bool>,
}

/// `Roam Research` API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub error: Option<bool>,
    pub message: Option<String>,
}

/// Datalog query result — raw array of tuples.
#[derive(Debug, Clone, Deserialize)]
pub struct QueryResult {
    pub result: Option<Vec<serde_json::Value>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn page_roundtrip() {
        let p: Page = serde_json::from_value(json!({
            "uid": "abc123",
            "title": "Daily Notes",
            "create-time": 1_709_251_200_000i64,
            "edit-time": 1_709_337_600_000i64,
        }))
        .unwrap();
        assert_eq!(p.uid, "abc123");
        assert_eq!(p.title, "Daily Notes");
        assert_eq!(p.create_time, Some(1_709_251_200_000));
        let re = serde_json::to_value(&p).unwrap();
        assert_eq!(re["title"], "Daily Notes");
    }

    #[test]
    fn page_minimal() {
        let p: Page = serde_json::from_value(json!({
            "uid": "x",
            "title": "T"
        }))
        .unwrap();
        assert_eq!(p.uid, "x");
        assert!(p.create_time.is_none());
        assert!(p.children.is_none());
    }

    #[test]
    fn page_with_children() {
        let p: Page = serde_json::from_value(json!({
            "uid": "p1",
            "title": "Test",
            "children": [{"uid": "b1", "string": "block content"}]
        }))
        .unwrap();
        assert_eq!(p.children.unwrap().len(), 1);
    }

    #[test]
    fn block_roundtrip() {
        let b: Block = serde_json::from_value(json!({
            "uid": "blk1",
            "string": "Hello world",
            "order": 0,
            "create-time": 1_709_251_200_000i64,
            "edit-time": 1_709_337_600_000i64,
            "open": true,
            "heading": 1,
        }))
        .unwrap();
        assert_eq!(b.uid, "blk1");
        assert_eq!(b.string, Some("Hello world".into()));
        assert_eq!(b.order, Some(0));
        assert_eq!(b.open, Some(true));
        assert_eq!(b.heading, Some(1));
    }

    #[test]
    fn block_minimal() {
        let b: Block = serde_json::from_value(json!({"uid": "b"})).unwrap();
        assert_eq!(b.uid, "b");
        assert!(b.string.is_none());
        assert!(b.order.is_none());
        assert!(b.children.is_none());
    }

    #[test]
    fn block_with_children() {
        let b: Block = serde_json::from_value(json!({
            "uid": "b1",
            "string": "parent",
            "children": [
                {"uid": "b2", "string": "child1"},
                {"uid": "b3", "string": "child2"}
            ]
        }))
        .unwrap();
        assert_eq!(b.children.unwrap().len(), 2);
    }

    #[test]
    fn page_list_roundtrip() {
        let pl: PageList = serde_json::from_value(json!({
            "pages": [
                {"uid": "p1", "title": "Page 1"},
                {"uid": "p2", "title": "Page 2"}
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
                {"uid": "b1", "string": "block 1"},
                {"uid": "b2", "string": "block 2"}
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
        let r: BlockCreateResponse = serde_json::from_value(json!({"uid": "new123"})).unwrap();
        assert_eq!(r.uid, "new123");
        let re = serde_json::to_value(&r).unwrap();
        assert_eq!(re["uid"], "new123");
    }

    #[test]
    fn datalog_query_roundtrip() {
        let q = DatalogQuery {
            query: "[:find ?title :where [?e :node/title ?title]]".into(),
            args: None,
        };
        let v = serde_json::to_value(&q).unwrap();
        assert_eq!(v["query"], "[:find ?title :where [?e :node/title ?title]]");
        assert!(v.get("args").is_none());
    }

    #[test]
    fn datalog_query_with_args() {
        let q = DatalogQuery {
            query: "[:find ?uid :in $ ?title :where [?e :node/title ?title] [?e :block/uid ?uid]]"
                .into(),
            args: Some(vec![json!("Daily Notes")]),
        };
        let v = serde_json::to_value(&q).unwrap();
        assert_eq!(v["args"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn write_action_roundtrip() {
        let wa = WriteAction {
            action: "create-block".into(),
            location: WriteLocation {
                parent_uid: "page1".into(),
                order: "last".into(),
            },
            block: WriteBlock {
                string: "New content".into(),
                uid: None,
                open: None,
            },
        };
        let v = serde_json::to_value(&wa).unwrap();
        assert_eq!(v["action"], "create-block");
        assert_eq!(v["location"]["parent-uid"], "page1");
        assert_eq!(v["location"]["order"], "last");
        assert_eq!(v["block"]["string"], "New content");
    }

    #[test]
    fn write_action_with_uid() {
        let wa = WriteAction {
            action: "create-block".into(),
            location: WriteLocation {
                parent_uid: "p1".into(),
                order: "0".into(),
            },
            block: WriteBlock {
                string: "Content".into(),
                uid: Some("custom-uid".into()),
                open: Some(true),
            },
        };
        let v = serde_json::to_value(&wa).unwrap();
        assert_eq!(v["block"]["uid"], "custom-uid");
        assert_eq!(v["block"]["open"], true);
    }

    #[test]
    fn write_location_roundtrip() {
        let loc: WriteLocation = serde_json::from_value(json!({
            "parent-uid": "abc",
            "order": "last"
        }))
        .unwrap();
        assert_eq!(loc.parent_uid, "abc");
        assert_eq!(loc.order, "last");
    }

    #[test]
    fn write_block_roundtrip() {
        let b: WriteBlock = serde_json::from_value(json!({
            "string": "hello"
        }))
        .unwrap();
        assert_eq!(b.string, "hello");
        assert!(b.uid.is_none());
    }

    #[test]
    fn api_error_response_with_message() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": true,
            "message": "Graph not found"
        }))
        .unwrap();
        assert_eq!(e.error, Some(true));
        assert_eq!(e.message, Some("Graph not found".into()));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.error.is_none());
        assert!(e.message.is_none());
    }

    #[test]
    fn api_error_response_error_false() {
        let e: ApiErrorResponse = serde_json::from_value(json!({"error": false})).unwrap();
        assert_eq!(e.error, Some(false));
    }

    #[test]
    fn query_result_with_data() {
        let qr: QueryResult = serde_json::from_value(json!({
            "result": [["page1", "Title 1"], ["page2", "Title 2"]]
        }))
        .unwrap();
        assert_eq!(qr.result.unwrap().len(), 2);
    }

    #[test]
    fn query_result_empty() {
        let qr: QueryResult = serde_json::from_value(json!({})).unwrap();
        assert!(qr.result.is_none());
    }

    #[test]
    fn query_result_empty_array() {
        let qr: QueryResult = serde_json::from_value(json!({"result": []})).unwrap();
        assert!(qr.result.unwrap().is_empty());
    }

    #[test]
    fn page_serialization_preserves_rename() {
        let p = Page {
            uid: "u1".into(),
            title: "T".into(),
            create_time: Some(1000),
            edit_time: Some(2000),
            children: None,
        };
        let v = serde_json::to_value(&p).unwrap();
        assert!(v.get("create-time").is_some());
        assert!(v.get("edit-time").is_some());
        assert!(v.get("create_time").is_none());
    }

    #[test]
    fn block_serialization_preserves_rename() {
        let b = Block {
            uid: "b1".into(),
            string: Some("s".into()),
            order: None,
            create_time: Some(100),
            edit_time: Some(200),
            children: None,
            open: None,
            heading: None,
        };
        let v = serde_json::to_value(&b).unwrap();
        assert!(v.get("create-time").is_some());
        assert!(v.get("edit-time").is_some());
    }

    // -- Additional Page tests --

    #[test]
    fn page_debug_format() {
        let p = Page {
            uid: "p1".into(),
            title: "Test".into(),
            create_time: None,
            edit_time: None,
            children: None,
        };
        let dbg = format!("{p:?}");
        assert!(dbg.contains("Page"));
        assert!(dbg.contains("p1"));
    }

    #[test]
    fn page_clone_is_equal() {
        let p = Page {
            uid: "p1".into(),
            title: "T".into(),
            create_time: Some(100),
            edit_time: Some(200),
            children: Some(vec![json!({"uid": "c1"})]),
        };
        let cloned = p.clone();
        assert_eq!(cloned.uid, p.uid);
        assert_eq!(cloned.title, p.title);
        assert_eq!(cloned.create_time, p.create_time);
    }

    #[test]
    fn page_json_string_roundtrip() {
        let p = Page {
            uid: "u1".into(),
            title: "My Page".into(),
            create_time: Some(1000),
            edit_time: Some(2000),
            children: None,
        };
        let s = serde_json::to_string(&p).unwrap();
        let back: Page = serde_json::from_str(&s).unwrap();
        assert_eq!(back.uid, "u1");
        assert_eq!(back.title, "My Page");
    }

    // -- Additional Block tests --

    #[test]
    fn block_debug_format() {
        let b = Block {
            uid: "b1".into(),
            string: Some("hello".into()),
            order: Some(0),
            create_time: None,
            edit_time: None,
            children: None,
            open: None,
            heading: None,
        };
        let dbg = format!("{b:?}");
        assert!(dbg.contains("Block"));
        assert!(dbg.contains("b1"));
    }

    #[test]
    fn block_clone_is_equal() {
        let b = Block {
            uid: "b1".into(),
            string: Some("content".into()),
            order: Some(5),
            create_time: Some(100),
            edit_time: Some(200),
            children: None,
            open: Some(true),
            heading: Some(2),
        };
        let cloned = b.clone();
        assert_eq!(cloned.uid, b.uid);
        assert_eq!(cloned.string, b.string);
        assert_eq!(cloned.order, b.order);
        assert_eq!(cloned.heading, b.heading);
    }

    #[test]
    fn block_heading_values() {
        for h in [1, 2, 3] {
            let b: Block = serde_json::from_value(json!({
                "uid": "b1",
                "heading": h
            }))
            .unwrap();
            assert_eq!(b.heading, Some(h));
        }
    }

    #[test]
    fn block_open_false() {
        let b: Block = serde_json::from_value(json!({
            "uid": "b1",
            "open": false
        }))
        .unwrap();
        assert_eq!(b.open, Some(false));
    }

    // -- DatalogQuery additional --

    #[test]
    fn datalog_query_debug_format() {
        let q = DatalogQuery {
            query: "[:find ?e]".into(),
            args: None,
        };
        let dbg = format!("{q:?}");
        assert!(dbg.contains("DatalogQuery"));
    }

    #[test]
    fn datalog_query_clone() {
        let q = DatalogQuery {
            query: "[:find ?e]".into(),
            args: Some(vec![json!("arg1"), json!(42)]),
        };
        let cloned = q.clone();
        assert_eq!(cloned.query, q.query);
        assert_eq!(cloned.args.unwrap().len(), 2);
    }

    #[test]
    fn datalog_query_multiple_args() {
        let q = DatalogQuery {
            query: "[:find ?e :in $ ?a ?b :where ...]".into(),
            args: Some(vec![json!("val1"), json!("val2"), json!(true)]),
        };
        let v = serde_json::to_value(&q).unwrap();
        assert_eq!(v["args"].as_array().unwrap().len(), 3);
    }

    // -- WriteAction additional --

    #[test]
    fn write_action_debug_format() {
        let wa = WriteAction {
            action: "create-block".into(),
            location: WriteLocation {
                parent_uid: "p1".into(),
                order: "last".into(),
            },
            block: WriteBlock {
                string: "content".into(),
                uid: None,
                open: None,
            },
        };
        let dbg = format!("{wa:?}");
        assert!(dbg.contains("WriteAction"));
        assert!(dbg.contains("create-block"));
    }

    #[test]
    fn write_block_with_open_false() {
        let wb = WriteBlock {
            string: "collapsed".into(),
            uid: Some("uid1".into()),
            open: Some(false),
        };
        let v = serde_json::to_value(&wb).unwrap();
        assert_eq!(v["open"], false);
        assert_eq!(v["uid"], "uid1");
    }

    #[test]
    fn write_block_skips_none_fields() {
        let wb = WriteBlock {
            string: "only content".into(),
            uid: None,
            open: None,
        };
        let v = serde_json::to_value(&wb).unwrap();
        assert!(v.get("uid").is_none());
        assert!(v.get("open").is_none());
    }

    // -- QueryResult additional --

    #[test]
    fn query_result_debug_format() {
        let qr = QueryResult {
            result: Some(vec![json!("a")]),
        };
        let dbg = format!("{qr:?}");
        assert!(dbg.contains("QueryResult"));
    }

    #[test]
    fn query_result_clone() {
        let qr = QueryResult {
            result: Some(vec![json!(1), json!(2)]),
        };
        let cloned = qr.clone();
        // Use original after clone
        assert!(qr.result.is_some());
        assert_eq!(cloned.result.unwrap().len(), 2);
    }

    // -- ApiErrorResponse additional --

    #[test]
    fn api_error_response_debug_format() {
        let e = ApiErrorResponse {
            error: Some(true),
            message: Some("test".into()),
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ApiErrorResponse"));
    }

    #[test]
    fn api_error_response_clone() {
        let e = ApiErrorResponse {
            error: Some(true),
            message: Some("msg".into()),
        };
        let cloned = e.clone();
        // Use original after clone
        assert_eq!(e.error, Some(true));
        assert_eq!(cloned.error, Some(true));
        assert_eq!(cloned.message, Some("msg".into()));
    }

    // -- PageList/BlockList additional --

    #[test]
    fn page_list_debug_format() {
        let pl = PageList { pages: vec![] };
        let dbg = format!("{pl:?}");
        assert!(dbg.contains("PageList"));
    }

    #[test]
    fn block_list_debug_format() {
        let bl = BlockList { blocks: vec![] };
        let dbg = format!("{bl:?}");
        assert!(dbg.contains("BlockList"));
    }

    #[test]
    fn block_create_response_debug_clone() {
        let r = BlockCreateResponse { uid: "new1".into() };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("BlockCreateResponse"));
        let cloned = r.clone();
        // Use original after clone
        assert_eq!(r.uid, "new1");
        assert_eq!(cloned.uid, "new1");
    }
}
