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
}
