//! `Reddit` API types.

use serde::{Deserialize, Serialize};

/// A `Reddit` post (link or self).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Post {
    pub name: Option<String>,
    pub title: Option<String>,
    pub selftext: Option<String>,
    pub author: Option<String>,
    pub subreddit: Option<String>,
    pub score: Option<i64>,
    pub num_comments: Option<i64>,
    pub permalink: Option<String>,
    pub url: Option<String>,
    pub created_utc: Option<f64>,
    pub over_18: Option<bool>,
    pub spoiler: Option<bool>,
    pub is_self: Option<bool>,
}

/// A `Reddit` comment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Comment {
    pub name: Option<String>,
    pub body: Option<String>,
    pub author: Option<String>,
    pub score: Option<i64>,
    pub created_utc: Option<f64>,
    pub parent_id: Option<String>,
    pub permalink: Option<String>,
}

/// `Reddit` API listing wrapper.
#[derive(Debug, Clone, Deserialize)]
pub struct Listing {
    pub data: ListingData,
}

/// Inner data of a `Reddit` listing.
#[derive(Debug, Clone, Deserialize)]
pub struct ListingData {
    #[serde(default)]
    pub children: Vec<Thing>,
    pub after: Option<String>,
}

/// A `Reddit` "thing" wrapper (t1_, t3_, etc.).
#[derive(Debug, Clone, Deserialize)]
pub struct Thing {
    pub kind: Option<String>,
    pub data: serde_json::Value,
}

/// `Reddit` API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub message: Option<String>,
    pub error: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn post_roundtrip() {
        let p: Post = serde_json::from_value(json!({
            "name": "t3_abc123", "title": "Test Post", "selftext": "body",
            "author": "testuser", "subreddit": "rust", "score": 42,
            "num_comments": 5, "permalink": "/r/rust/comments/abc123/test/",
            "created_utc": 1709600000.0, "over_18": false, "spoiler": false, "is_self": true
        })).unwrap();
        assert_eq!(p.name.as_deref(), Some("t3_abc123"));
        assert_eq!(p.score, Some(42));
        assert!(p.is_self.unwrap());
    }

    #[test]
    fn post_minimal() {
        let p: Post = serde_json::from_value(json!({})).unwrap();
        assert!(p.name.is_none());
    }

    #[test]
    fn comment_roundtrip() {
        let c: Comment = serde_json::from_value(json!({
            "name": "t1_xyz", "body": "Great post!", "author": "user2",
            "score": 10, "created_utc": 1709600100.0, "parent_id": "t3_abc123"
        })).unwrap();
        assert_eq!(c.name.as_deref(), Some("t1_xyz"));
        assert_eq!(c.score, Some(10));
    }

    #[test]
    fn listing_roundtrip() {
        let l: Listing = serde_json::from_value(json!({
            "data": {
                "children": [
                    {"kind": "t3", "data": {"name": "t3_abc", "title": "Hello"}}
                ],
                "after": "t3_next"
            }
        })).unwrap();
        assert_eq!(l.data.children.len(), 1);
        assert_eq!(l.data.after.as_deref(), Some("t3_next"));
    }

    #[test]
    fn listing_empty() {
        let l: Listing = serde_json::from_value(json!({
            "data": { "children": [], "after": null }
        })).unwrap();
        assert!(l.data.children.is_empty());
        assert!(l.data.after.is_none());
    }

    #[test]
    fn api_error_response() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "Forbidden", "error": 403
        })).unwrap();
        assert_eq!(e.message.as_deref(), Some("Forbidden"));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.message.is_none());
    }

    // ── Post additional tests ───────────────────────────────────────

    #[test]
    fn post_serialize_roundtrip() {
        let p = Post {
            name: Some("t3_test".into()),
            title: Some("Serialize Test".into()),
            selftext: Some("body".into()),
            author: Some("user".into()),
            subreddit: Some("test".into()),
            score: Some(100),
            num_comments: Some(10),
            permalink: Some("/r/test/comments/test/".into()),
            url: Some("https://reddit.com".into()),
            created_utc: Some(1700000000.0),
            over_18: Some(false),
            spoiler: Some(false),
            is_self: Some(true),
        };
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["name"], "t3_test");
        assert_eq!(v["score"], 100);
        let p2: Post = serde_json::from_value(v).unwrap();
        assert_eq!(p2.name, Some("t3_test".into()));
    }

    #[test]
    fn post_clone() {
        let p: Post = serde_json::from_value(json!({
            "name": "t3_clone", "title": "Clone Test"
        })).unwrap();
        #[allow(clippy::redundant_clone)]
        let p2 = p.clone();
        assert_eq!(p2.name, Some("t3_clone".into()));
        assert_eq!(p2.title, Some("Clone Test".into()));
    }

    #[test]
    fn post_debug() {
        let p: Post = serde_json::from_value(json!({"name": "t3_dbg"})).unwrap();
        let dbg = format!("{p:?}");
        assert!(dbg.contains("t3_dbg"));
    }

    #[test]
    fn post_negative_score() {
        let p: Post = serde_json::from_value(json!({
            "score": -42, "num_comments": 0
        })).unwrap();
        assert_eq!(p.score, Some(-42));
        assert_eq!(p.num_comments, Some(0));
    }

    #[test]
    fn post_over_18_true() {
        let p: Post = serde_json::from_value(json!({"over_18": true})).unwrap();
        assert_eq!(p.over_18, Some(true));
    }

    // ── Comment additional tests ────────────────────────────────────

    #[test]
    fn comment_serialize_roundtrip() {
        let c = Comment {
            name: Some("t1_ser".into()),
            body: Some("Nice!".into()),
            author: Some("commenter".into()),
            score: Some(5),
            created_utc: Some(1700000100.0),
            parent_id: Some("t3_parent".into()),
            permalink: Some("/r/test/comments/test/c1".into()),
        };
        let v = serde_json::to_value(&c).unwrap();
        assert_eq!(v["body"], "Nice!");
        let c2: Comment = serde_json::from_value(v).unwrap();
        assert_eq!(c2.name, Some("t1_ser".into()));
    }

    #[test]
    fn comment_minimal() {
        let c: Comment = serde_json::from_value(json!({})).unwrap();
        assert!(c.name.is_none());
        assert!(c.body.is_none());
        assert!(c.author.is_none());
    }

    #[test]
    fn comment_clone() {
        let c: Comment = serde_json::from_value(json!({"name": "t1_cl"})).unwrap();
        #[allow(clippy::redundant_clone)]
        let c2 = c.clone();
        assert_eq!(c2.name, Some("t1_cl".into()));
    }

    #[test]
    fn comment_debug() {
        let c: Comment = serde_json::from_value(json!({"body": "debug body"})).unwrap();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("debug body"));
    }

    #[test]
    fn comment_negative_score() {
        let c: Comment = serde_json::from_value(json!({"score": -10})).unwrap();
        assert_eq!(c.score, Some(-10));
    }

    // ── Listing additional tests ────────────────────────────────────

    #[test]
    fn listing_clone() {
        let l: Listing = serde_json::from_value(json!({
            "data": { "children": [], "after": null }
        })).unwrap();
        #[allow(clippy::redundant_clone)]
        let l2 = l.clone();
        assert!(l2.data.children.is_empty());
    }

    #[test]
    fn listing_debug() {
        let l: Listing = serde_json::from_value(json!({
            "data": { "children": [], "after": "cursor" }
        })).unwrap();
        let dbg = format!("{l:?}");
        assert!(dbg.contains("cursor"));
    }

    #[test]
    fn listing_default_children() {
        // children uses #[serde(default)] so omitting it should work
        let l: Listing = serde_json::from_value(json!({
            "data": { "after": null }
        })).unwrap();
        assert!(l.data.children.is_empty());
    }

    #[test]
    fn listing_many_children() {
        let children: Vec<serde_json::Value> = (0..50)
            .map(|i| json!({"kind": "t3", "data": {"name": format!("t3_{i}")}}))
            .collect();
        let l: Listing = serde_json::from_value(json!({
            "data": { "children": children, "after": "t3_49" }
        })).unwrap();
        assert_eq!(l.data.children.len(), 50);
    }

    // ── Thing tests ─────────────────────────────────────────────────

    #[test]
    fn thing_clone() {
        let t: Thing = serde_json::from_value(json!({"kind": "t3", "data": {}})).unwrap();
        #[allow(clippy::redundant_clone)]
        let t2 = t.clone();
        assert_eq!(t2.kind, Some("t3".into()));
    }

    #[test]
    fn thing_debug() {
        let t: Thing = serde_json::from_value(json!({"kind": "t1", "data": {"id": 1}})).unwrap();
        let dbg = format!("{t:?}");
        assert!(dbg.contains("t1"));
    }

    #[test]
    fn thing_no_kind() {
        let t: Thing = serde_json::from_value(json!({"data": {}})).unwrap();
        assert!(t.kind.is_none());
    }

    // ── ApiErrorResponse additional tests ───────────────────────────

    #[test]
    fn api_error_response_clone() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "err", "error": 500
        })).unwrap();
        #[allow(clippy::redundant_clone)]
        let e2 = e.clone();
        assert_eq!(e2.message, Some("err".into()));
    }

    #[test]
    fn api_error_response_debug() {
        let e: ApiErrorResponse = serde_json::from_value(json!({"message": "debug_test"})).unwrap();
        let dbg = format!("{e:?}");
        assert!(dbg.contains("debug_test"));
    }

    #[test]
    fn api_error_response_error_as_string() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "Bad Request",
            "error": "invalid_grant"
        })).unwrap();
        assert_eq!(e.error.unwrap().as_str(), Some("invalid_grant"));
    }
}
