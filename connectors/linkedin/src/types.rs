//! LinkedIn API types.

#![allow(clippy::doc_markdown)]

use serde::{Deserialize, Serialize};

/// A LinkedIn user profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub id: Option<String>,
    #[serde(rename = "localizedFirstName")]
    pub localized_first_name: Option<String>,
    #[serde(rename = "localizedLastName")]
    pub localized_last_name: Option<String>,
    #[serde(rename = "localizedHeadline")]
    pub localized_headline: Option<String>,
}

/// A LinkedIn organization/company.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub id: Option<String>,
    #[serde(rename = "localizedName")]
    pub localized_name: Option<String>,
    #[serde(rename = "vanityName")]
    pub vanity_name: Option<String>,
    #[serde(rename = "localizedDescription")]
    pub localized_description: Option<String>,
}

/// A LinkedIn UGC post.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Post {
    pub id: Option<String>,
    pub author: Option<String>,
    #[serde(rename = "lifecycleState")]
    pub lifecycle_state: Option<String>,
    #[serde(rename = "specificContent")]
    pub specific_content: Option<serde_json::Value>,
}

/// Share statistics from LinkedIn analytics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareStatistic {
    #[serde(rename = "totalShareStatistics")]
    pub total_share_statistics: Option<serde_json::Value>,
}

/// LinkedIn API error response body.
///
/// LinkedIn returns `{"message": "...", "serviceErrorCode": 123, "status": 401}` on errors.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    /// The error message from LinkedIn.
    pub message: Option<String>,
    /// The service-specific error code.
    #[serde(rename = "serviceErrorCode")]
    pub service_error_code: Option<u32>,
    /// The HTTP status code echoed in the body.
    pub status: Option<u16>,
}

/// LinkedIn search result element.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub elements: Option<Vec<serde_json::Value>>,
}

/// LinkedIn connection element.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub id: Option<String>,
    #[serde(rename = "firstName")]
    pub first_name: Option<String>,
    #[serde(rename = "lastName")]
    pub last_name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn profile_roundtrip() {
        let p: Profile = serde_json::from_value(json!({
            "id": "abc123",
            "localizedFirstName": "Jane",
            "localizedLastName": "Doe",
            "localizedHeadline": "Software Engineer at ACME",
        }))
        .unwrap();
        assert_eq!(p.id, Some("abc123".into()));
        assert_eq!(p.localized_first_name, Some("Jane".into()));
        assert_eq!(p.localized_last_name, Some("Doe".into()));
        assert_eq!(
            p.localized_headline,
            Some("Software Engineer at ACME".into())
        );
        let re = serde_json::to_value(&p).unwrap();
        assert_eq!(re["localizedFirstName"], "Jane");
    }

    #[test]
    fn profile_minimal() {
        let p: Profile = serde_json::from_value(json!({})).unwrap();
        assert!(p.id.is_none());
        assert!(p.localized_first_name.is_none());
        assert!(p.localized_last_name.is_none());
        assert!(p.localized_headline.is_none());
    }

    #[test]
    fn organization_roundtrip() {
        let o: Organization = serde_json::from_value(json!({
            "id": "org_456",
            "localizedName": "ACME Corp",
            "vanityName": "acme",
            "localizedDescription": "Leading technology company",
        }))
        .unwrap();
        assert_eq!(o.id, Some("org_456".into()));
        assert_eq!(o.localized_name, Some("ACME Corp".into()));
        assert_eq!(o.vanity_name, Some("acme".into()));
        assert_eq!(
            o.localized_description,
            Some("Leading technology company".into())
        );
        let re = serde_json::to_value(&o).unwrap();
        assert_eq!(re["localizedName"], "ACME Corp");
    }

    #[test]
    fn organization_minimal() {
        let o: Organization = serde_json::from_value(json!({})).unwrap();
        assert!(o.id.is_none());
        assert!(o.localized_name.is_none());
        assert!(o.vanity_name.is_none());
        assert!(o.localized_description.is_none());
    }

    #[test]
    fn post_roundtrip() {
        let p: Post = serde_json::from_value(json!({
            "id": "urn:li:share:12345",
            "author": "urn:li:person:abc123",
            "lifecycleState": "PUBLISHED",
            "specificContent": {
                "com.linkedin.ugc.ShareContent": {
                    "shareCommentary": {"text": "Hello world"}
                }
            },
        }))
        .unwrap();
        assert_eq!(p.id, Some("urn:li:share:12345".into()));
        assert_eq!(p.author, Some("urn:li:person:abc123".into()));
        assert_eq!(p.lifecycle_state, Some("PUBLISHED".into()));
        assert!(p.specific_content.is_some());
        let re = serde_json::to_value(&p).unwrap();
        assert_eq!(re["lifecycleState"], "PUBLISHED");
    }

    #[test]
    fn post_minimal() {
        let p: Post = serde_json::from_value(json!({})).unwrap();
        assert!(p.id.is_none());
        assert!(p.author.is_none());
        assert!(p.lifecycle_state.is_none());
        assert!(p.specific_content.is_none());
    }

    #[test]
    fn share_statistic_roundtrip() {
        let s: ShareStatistic = serde_json::from_value(json!({
            "totalShareStatistics": {
                "shareCount": 42,
                "clickCount": 150,
                "likeCount": 73,
            }
        }))
        .unwrap();
        assert!(s.total_share_statistics.is_some());
        let stats = s.total_share_statistics.unwrap();
        assert_eq!(stats["shareCount"], 42);
    }

    #[test]
    fn share_statistic_minimal() {
        let s: ShareStatistic = serde_json::from_value(json!({})).unwrap();
        assert!(s.total_share_statistics.is_none());
    }

    #[test]
    fn api_error_response_full() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "Invalid access token",
            "serviceErrorCode": 65601,
            "status": 401,
        }))
        .unwrap();
        assert_eq!(e.message, Some("Invalid access token".into()));
        assert_eq!(e.service_error_code, Some(65601));
        assert_eq!(e.status, Some(401));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.message.is_none());
        assert!(e.service_error_code.is_none());
        assert!(e.status.is_none());
    }

    #[test]
    fn api_error_response_message_only() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "Resource not found",
        }))
        .unwrap();
        assert_eq!(e.message, Some("Resource not found".into()));
        assert!(e.service_error_code.is_none());
    }

    #[test]
    fn search_result_roundtrip() {
        let s: SearchResult = serde_json::from_value(json!({
            "elements": [
                {"name": "ACME Corp"},
                {"name": "Beta Inc"},
            ]
        }))
        .unwrap();
        assert_eq!(s.elements.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn search_result_empty() {
        let s: SearchResult = serde_json::from_value(json!({"elements": []})).unwrap();
        assert!(s.elements.as_ref().unwrap().is_empty());
    }

    #[test]
    fn connection_roundtrip() {
        let c: Connection = serde_json::from_value(json!({
            "id": "conn_789",
            "firstName": "Bob",
            "lastName": "Smith",
        }))
        .unwrap();
        assert_eq!(c.id, Some("conn_789".into()));
        assert_eq!(c.first_name, Some("Bob".into()));
        assert_eq!(c.last_name, Some("Smith".into()));
    }

    #[test]
    fn connection_minimal() {
        let c: Connection = serde_json::from_value(json!({})).unwrap();
        assert!(c.id.is_none());
        assert!(c.first_name.is_none());
        assert!(c.last_name.is_none());
    }

    #[test]
    fn profile_extra_fields_ignored() {
        let p: Profile = serde_json::from_value(json!({
            "id": "abc",
            "localizedFirstName": "Test",
            "unknown_field": "should be ignored",
        }))
        .unwrap();
        assert_eq!(p.id, Some("abc".into()));
        assert_eq!(p.localized_first_name, Some("Test".into()));
    }

    #[test]
    fn organization_extra_fields_ignored() {
        let o: Organization = serde_json::from_value(json!({
            "id": "org1",
            "localizedName": "Test",
            "extra": 42,
        }))
        .unwrap();
        assert_eq!(o.id, Some("org1".into()));
        assert_eq!(o.localized_name, Some("Test".into()));
    }

    #[test]
    fn post_extra_fields_ignored() {
        let p: Post = serde_json::from_value(json!({
            "id": "post1",
            "author": "urn:li:person:x",
            "extra_bool": true,
        }))
        .unwrap();
        assert_eq!(p.id, Some("post1".into()));
        assert_eq!(p.author, Some("urn:li:person:x".into()));
    }

    #[test]
    fn profile_serialize_roundtrip() {
        let p = Profile {
            id: Some("p1".into()),
            localized_first_name: Some("Alice".into()),
            localized_last_name: Some("Wonder".into()),
            localized_headline: None,
        };
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["id"], "p1");
        assert_eq!(v["localizedFirstName"], "Alice");
        assert_eq!(v["localizedLastName"], "Wonder");
        assert!(v["localizedHeadline"].is_null());
    }

    #[test]
    fn organization_serialize_roundtrip() {
        let o = Organization {
            id: Some("o1".into()),
            localized_name: Some("Corp".into()),
            vanity_name: Some("corp".into()),
            localized_description: None,
        };
        let v = serde_json::to_value(&o).unwrap();
        assert_eq!(v["id"], "o1");
        assert_eq!(v["localizedName"], "Corp");
        assert_eq!(v["vanityName"], "corp");
    }

    #[test]
    fn post_serialize_roundtrip() {
        let p = Post {
            id: Some("p1".into()),
            author: Some("urn:li:person:x".into()),
            lifecycle_state: Some("PUBLISHED".into()),
            specific_content: Some(json!({"text": "hello"})),
        };
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["id"], "p1");
        assert_eq!(v["lifecycleState"], "PUBLISHED");
        assert_eq!(v["specificContent"]["text"], "hello");
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn profile_clone() {
        let p = Profile {
            id: Some("p1".into()),
            localized_first_name: Some("Jane".into()),
            localized_last_name: Some("Doe".into()),
            localized_headline: None,
        };
        let c = p.clone();
        assert_eq!(c.id, Some("p1".into()));
        assert_eq!(c.localized_first_name, Some("Jane".into()));
    }

    #[test]
    fn profile_debug() {
        let p = Profile {
            id: Some("p1".into()),
            localized_first_name: None,
            localized_last_name: None,
            localized_headline: None,
        };
        let dbg = format!("{p:?}");
        assert!(dbg.contains("Profile"));
        assert!(dbg.contains("p1"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn organization_clone() {
        let o = Organization {
            id: Some("o1".into()),
            localized_name: Some("Corp".into()),
            vanity_name: None,
            localized_description: None,
        };
        let c = o.clone();
        assert_eq!(c.id, Some("o1".into()));
    }

    #[test]
    fn organization_debug() {
        let o = Organization {
            id: Some("o1".into()),
            localized_name: None,
            vanity_name: None,
            localized_description: None,
        };
        let dbg = format!("{o:?}");
        assert!(dbg.contains("Organization"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn post_clone() {
        let p = Post {
            id: Some("post1".into()),
            author: Some("urn:li:person:x".into()),
            lifecycle_state: None,
            specific_content: None,
        };
        let c = p.clone();
        assert_eq!(c.id, Some("post1".into()));
        assert_eq!(c.author, Some("urn:li:person:x".into()));
    }

    #[test]
    fn post_debug() {
        let p = Post {
            id: Some("post1".into()),
            author: None,
            lifecycle_state: None,
            specific_content: None,
        };
        let dbg = format!("{p:?}");
        assert!(dbg.contains("Post"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn share_statistic_clone() {
        let s = ShareStatistic {
            total_share_statistics: Some(json!({"shareCount": 5})),
        };
        let c = s.clone();
        assert_eq!(c.total_share_statistics.unwrap()["shareCount"], 5);
    }

    #[test]
    fn share_statistic_debug() {
        let s = ShareStatistic {
            total_share_statistics: None,
        };
        let dbg = format!("{s:?}");
        assert!(dbg.contains("ShareStatistic"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn api_error_response_clone() {
        let e = ApiErrorResponse {
            message: Some("error msg".into()),
            service_error_code: Some(123),
            status: Some(400),
        };
        let c = e.clone();
        assert_eq!(c.message, Some("error msg".into()));
        assert_eq!(c.service_error_code, Some(123));
        assert_eq!(c.status, Some(400));
    }

    #[test]
    fn api_error_response_debug() {
        let e = ApiErrorResponse {
            message: None,
            service_error_code: None,
            status: None,
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ApiErrorResponse"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn search_result_clone() {
        let s = SearchResult {
            elements: Some(vec![json!({"name": "ACME"})]),
        };
        let c = s.clone();
        assert_eq!(c.elements.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn search_result_debug() {
        let s = SearchResult { elements: None };
        let dbg = format!("{s:?}");
        assert!(dbg.contains("SearchResult"));
    }

    #[test]
    fn search_result_minimal() {
        let s: SearchResult = serde_json::from_value(json!({})).unwrap();
        assert!(s.elements.is_none());
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn connection_clone() {
        let c = Connection {
            id: Some("c1".into()),
            first_name: Some("Bob".into()),
            last_name: Some("Smith".into()),
        };
        let cl = c.clone();
        assert_eq!(cl.id, Some("c1".into()));
    }

    #[test]
    fn connection_debug() {
        let c = Connection {
            id: None,
            first_name: None,
            last_name: None,
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("Connection"));
    }

    #[test]
    fn connection_serialize_roundtrip() {
        let c = Connection {
            id: Some("conn1".into()),
            first_name: Some("Alice".into()),
            last_name: Some("Wonder".into()),
        };
        let v = serde_json::to_value(&c).unwrap();
        assert_eq!(v["id"], "conn1");
        assert_eq!(v["firstName"], "Alice");
        assert_eq!(v["lastName"], "Wonder");
    }

    #[test]
    fn profile_null_fields_serialize_as_null() {
        let p = Profile {
            id: None,
            localized_first_name: None,
            localized_last_name: None,
            localized_headline: None,
        };
        let v = serde_json::to_value(&p).unwrap();
        assert!(v["id"].is_null());
        assert!(v["localizedFirstName"].is_null());
    }

    #[test]
    fn share_statistic_serialize() {
        let s = ShareStatistic {
            total_share_statistics: Some(json!({"clicks": 100})),
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["totalShareStatistics"]["clicks"], 100);
    }
}
