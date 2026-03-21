//! Confluence API types.

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Space types
// ─────────────────────────────────────────────────────────────────────────────

/// Confluence space representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Space {
    pub id: String,
    pub key: String,
    pub name: String,
    #[serde(rename = "type", default)]
    pub space_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<SpaceDescription>,
    #[serde(rename = "_links", skip_serializing_if = "Option::is_none")]
    pub links: Option<Links>,
}

/// Space description container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpaceDescription {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plain: Option<ContentBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub view: Option<ContentBody>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Page types
// ─────────────────────────────────────────────────────────────────────────────

/// Confluence page representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page {
    pub id: String,
    pub title: String,
    #[serde(rename = "type", default)]
    pub page_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space: Option<SpaceRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<Version>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<PageBody>,
    #[serde(rename = "_links", skip_serializing_if = "Option::is_none")]
    pub links: Option<Links>,
}

/// Minimal space reference embedded in a page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpaceRef {
    pub key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Page version info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Version {
    pub number: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub when: Option<String>,
    #[serde(rename = "minorEdit", skip_serializing_if = "Option::is_none")]
    pub minor_edit: Option<bool>,
}

/// Page body container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage: Option<ContentBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub view: Option<ContentBody>,
}

/// Content body with representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentBody {
    pub value: String,
    pub representation: String,
}

/// Links container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Links {
    #[serde(rename = "self", skip_serializing_if = "Option::is_none")]
    pub self_link: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webui: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Request types
// ─────────────────────────────────────────────────────────────────────────────

/// Request to create a page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePageRequest {
    #[serde(rename = "type")]
    pub page_type: String,
    pub title: String,
    pub space: SpaceRef,
    pub body: PageBody,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ancestors: Option<Vec<PageAncestor>>,
}

/// Parent page reference for creating sub-pages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageAncestor {
    pub id: String,
}

/// Request to update a page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePageRequest {
    pub id: String,
    #[serde(rename = "type")]
    pub page_type: String,
    pub title: String,
    pub body: PageBody,
    pub version: Version,
}

// ─────────────────────────────────────────────────────────────────────────────
// Search types
// ─────────────────────────────────────────────────────────────────────────────

/// CQL search result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub content: Option<Page>,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub excerpt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Response types
// ─────────────────────────────────────────────────────────────────────────────

/// Paginated response envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    pub results: Vec<T>,
    #[serde(default)]
    pub start: u64,
    #[serde(default)]
    pub limit: u64,
    #[serde(default)]
    pub size: u64,
    #[serde(rename = "_links", skip_serializing_if = "Option::is_none")]
    pub links: Option<PaginationLinks>,
}

/// Pagination links.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationLinks {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
}

/// Confluence API error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorResponse {
    #[serde(default, rename = "statusCode")]
    pub status_code: u16,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn space_deserialization() {
        let json = serde_json::json!({
            "id": "123",
            "key": "DEV",
            "name": "Development",
            "type": "global",
            "status": "current",
            "_links": {
                "self": "https://example.atlassian.net/wiki/rest/api/space/DEV",
                "webui": "/spaces/DEV"
            }
        });
        let space: Space = serde_json::from_value(json).unwrap();
        assert_eq!(space.id, "123");
        assert_eq!(space.key, "DEV");
        assert_eq!(space.name, "Development");
    }

    #[test]
    fn page_deserialization() {
        let json = serde_json::json!({
            "id": "456",
            "title": "Getting Started",
            "type": "page",
            "status": "current",
            "space": { "key": "DEV" },
            "version": { "number": 3, "message": "Updated intro" },
            "body": {
                "storage": {
                    "value": "<p>Hello</p>",
                    "representation": "storage"
                }
            }
        });
        let page: Page = serde_json::from_value(json).unwrap();
        assert_eq!(page.id, "456");
        assert_eq!(page.title, "Getting Started");
        assert_eq!(page.version.unwrap().number, 3);
    }

    #[test]
    fn search_result_deserialization() {
        let json = serde_json::json!({
            "title": "API Guide",
            "excerpt": "This guide explains...",
            "url": "/wiki/spaces/DEV/pages/789",
            "content": {
                "id": "789",
                "title": "API Guide",
                "type": "page"
            }
        });
        let result: SearchResult = serde_json::from_value(json).unwrap();
        assert_eq!(result.title, "API Guide");
        assert!(result.content.is_some());
    }

    #[test]
    fn paginated_response_deserialization() {
        let json = serde_json::json!({
            "results": [
                { "id": "1", "key": "SPACE1", "name": "Space One", "type": "global" }
            ],
            "start": 0,
            "limit": 25,
            "size": 1,
            "_links": { "next": "/rest/api/space?start=25" }
        });
        let resp: PaginatedResponse<Space> = serde_json::from_value(json).unwrap();
        assert_eq!(resp.results.len(), 1);
        assert_eq!(resp.size, 1);
    }

    #[test]
    fn create_page_request_serialization() {
        let req = CreatePageRequest {
            page_type: "page".into(),
            title: "New Page".into(),
            space: SpaceRef {
                key: "DEV".into(),
                name: None,
            },
            body: PageBody {
                storage: Some(ContentBody {
                    value: "<p>Content</p>".into(),
                    representation: "storage".into(),
                }),
                view: None,
            },
            ancestors: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["title"], "New Page");
        assert_eq!(json["type"], "page");
        assert_eq!(json["space"]["key"], "DEV");
    }

    #[test]
    fn update_page_request_serialization() {
        let req = UpdatePageRequest {
            id: "456".into(),
            page_type: "page".into(),
            title: "Updated Title".into(),
            body: PageBody {
                storage: Some(ContentBody {
                    value: "<p>Updated</p>".into(),
                    representation: "storage".into(),
                }),
                view: None,
            },
            version: Version {
                number: 4,
                message: Some("Updated content".into()),
                when: None,
                minor_edit: Some(false),
            },
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["version"]["number"], 4);
    }

    #[test]
    fn api_error_deserialization() {
        let json = serde_json::json!({
            "statusCode": 404,
            "message": "Page not found",
            "reason": "No page with id 999"
        });
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.status_code, 404);
        assert_eq!(err.message, "Page not found");
    }

    #[test]
    fn page_with_ancestors() {
        let req = CreatePageRequest {
            page_type: "page".into(),
            title: "Child Page".into(),
            space: SpaceRef {
                key: "DEV".into(),
                name: None,
            },
            body: PageBody {
                storage: Some(ContentBody {
                    value: "<p>Child</p>".into(),
                    representation: "storage".into(),
                }),
                view: None,
            },
            ancestors: Some(vec![PageAncestor { id: "456".into() }]),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["ancestors"][0]["id"], "456");
    }

    #[test]
    fn space_minimal_deserialization() {
        let json = serde_json::json!({
            "id": "1",
            "key": "TS",
            "name": "Test"
        });
        let space: Space = serde_json::from_value(json).unwrap();
        assert_eq!(space.space_type, ""); // default
    }

    #[test]
    fn page_minimal_deserialization() {
        let json = serde_json::json!({
            "id": "1",
            "title": "Minimal"
        });
        let page: Page = serde_json::from_value(json).unwrap();
        assert_eq!(page.title, "Minimal");
        assert!(page.space.is_none());
        assert!(page.version.is_none());
    }
}
