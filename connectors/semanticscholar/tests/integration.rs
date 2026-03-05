//! Integration tests for the FCP Semantic Scholar connector.

#![allow(
    clippy::cast_possible_truncation,
    clippy::doc_markdown,
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use serde_json::json;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_semanticscholar::connector::SemanticScholarConnector;

async fn setup_connector(mock_url: &str) -> SemanticScholarConnector {
    let mut c = SemanticScholarConnector::new();
    c.handle_configure(json!({ "api_key": "test-api-key-123", "base_url": mock_url }))
        .await
        .unwrap();
    c.handle_handshake(json!({"session_id": "test"}))
        .await
        .unwrap();
    c
}

async fn setup_connector_no_key(mock_url: &str) -> SemanticScholarConnector {
    let mut c = SemanticScholarConnector::new();
    c.handle_configure(json!({ "base_url": mock_url }))
        .await
        .unwrap();
    c.handle_handshake(json!({"session_id": "test"}))
        .await
        .unwrap();
    c
}

// -- Lifecycle --

#[tokio::test]
async fn lifecycle_health_unconfigured() {
    let c = SemanticScholarConnector::new();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "unconfigured");
}

#[tokio::test]
async fn lifecycle_full() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "healthy");
}

#[tokio::test]
async fn lifecycle_configured_but_not_handshaken() {
    let server = MockServer::start().await;
    let mut c = SemanticScholarConnector::new();
    c.handle_configure(json!({ "base_url": server.uri() }))
        .await
        .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "degraded");
}

#[tokio::test]
async fn lifecycle_handshake_before_configure_fails() {
    let mut c = SemanticScholarConnector::new();
    assert!(c.handle_handshake(json!({})).await.is_err());
}

#[tokio::test]
async fn lifecycle_shutdown() {
    let server = MockServer::start().await;
    let mut c = setup_connector(&server.uri()).await;
    c.handle_shutdown(json!({})).await.unwrap();
    assert_eq!(c.handle_health().await.unwrap()["status"], "unconfigured");
}

#[tokio::test]
async fn lifecycle_self_check_configured() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "ready");
    assert_eq!(check["connector_id"], "fcp.semanticscholar");
}

#[tokio::test]
async fn lifecycle_self_check_unconfigured() {
    let c = SemanticScholarConnector::new();
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "unconfigured");
}

#[tokio::test]
async fn lifecycle_doctor_healthy() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let doc = c.handle_doctor().await.unwrap();
    assert_eq!(doc["status"], "healthy");
}

#[tokio::test]
async fn lifecycle_doctor_no_key_degraded() {
    let server = MockServer::start().await;
    let c = setup_connector_no_key(&server.uri()).await;
    let doc = c.handle_doctor().await.unwrap();
    // Without api_key, the api_key check is non-critical but fails => degraded
    assert_eq!(doc["status"], "degraded");
}

#[tokio::test]
async fn lifecycle_doctor_unconfigured() {
    let c = SemanticScholarConnector::new();
    let doc = c.handle_doctor().await.unwrap();
    assert_eq!(doc["status"], "unhealthy");
}

#[tokio::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    assert_eq!(intro["operations"].as_array().unwrap().len(), 7);
    assert_eq!(intro["connector_id"], "fcp.semanticscholar");
}

#[tokio::test]
async fn lifecycle_configure_no_key() {
    let server = MockServer::start().await;
    let mut c = SemanticScholarConnector::new();
    c.handle_configure(json!({ "base_url": server.uri() }))
        .await
        .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["configured"], true);
}

// -- Paper Search --

#[tokio::test]
async fn paper_search() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/paper/search"))
        .and(query_param("query", "attention mechanism"))
        .and(header("x-api-key", "test-api-key-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 1000,
            "offset": 0,
            "next": 10,
            "data": [
                {"paperId": "p1", "title": "Attention Is All You Need"},
                {"paperId": "p2", "title": "BERT"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "semanticscholar.paper.search",
            "input": {"query": "attention mechanism"}
        }))
        .await
        .unwrap();
    assert_eq!(result["total"], 1000);
    assert_eq!(result["data"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn paper_search_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/paper/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 0,
            "data": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "semanticscholar.paper.search",
            "input": {"query": "nonexistent topic xyz"}
        }))
        .await
        .unwrap();
    assert_eq!(result["total"], 0);
    assert!(result["data"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn paper_search_missing_query() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "semanticscholar.paper.search",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn paper_search_with_limit_and_offset() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/paper/search"))
        .and(query_param("query", "transformers"))
        .and(query_param("limit", "5"))
        .and(query_param("offset", "10"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 100,
            "offset": 10,
            "next": 15,
            "data": [{"paperId": "p1"}]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "semanticscholar.paper.search",
            "input": {"query": "transformers", "limit": 5, "offset": 10}
        }))
        .await
        .unwrap();
    assert_eq!(result["offset"], 10);
}

// -- Paper Get --

#[tokio::test]
async fn paper_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/paper/649def34f8be52c8b66281af98ae884c09aef38b"))
        .and(header("x-api-key", "test-api-key-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "paperId": "649def34f8be52c8b66281af98ae884c09aef38b",
            "title": "Attention Is All You Need",
            "year": 2017,
            "citationCount": 50000,
            "authors": [
                {"authorId": "1", "name": "Ashish Vaswani"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "semanticscholar.paper.get",
            "input": {"paper_id": "649def34f8be52c8b66281af98ae884c09aef38b"}
        }))
        .await
        .unwrap();
    assert_eq!(result["paperId"], "649def34f8be52c8b66281af98ae884c09aef38b");
    assert_eq!(result["title"], "Attention Is All You Need");
    assert_eq!(result["year"], 2017);
}

#[tokio::test]
async fn paper_get_missing_paper_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "semanticscholar.paper.get",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn paper_get_with_fields() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/paper/abc123"))
        .and(query_param("fields", "title,year"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "paperId": "abc123",
            "title": "Test Paper",
            "year": 2023,
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "semanticscholar.paper.get",
            "input": {"paper_id": "abc123", "fields": "title,year"}
        }))
        .await
        .unwrap();
    assert_eq!(result["paperId"], "abc123");
}

// -- Paper Citations --

#[tokio::test]
async fn paper_citations() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/paper/abc123/citations"))
        .and(header("x-api-key", "test-api-key-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "offset": 0,
            "data": [
                {"citingPaper": {"paperId": "c1", "title": "Citing Paper 1"}},
                {"citingPaper": {"paperId": "c2", "title": "Citing Paper 2"}},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "semanticscholar.paper.citations",
            "input": {"paper_id": "abc123"}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn paper_citations_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/paper/abc123/citations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "semanticscholar.paper.citations",
            "input": {"paper_id": "abc123"}
        }))
        .await
        .unwrap();
    assert!(result["data"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn paper_citations_missing_paper_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "semanticscholar.paper.citations",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn paper_citations_with_limit() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/paper/abc123/citations"))
        .and(query_param("limit", "5"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"citingPaper": {"paperId": "c1"}}]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "semanticscholar.paper.citations",
            "input": {"paper_id": "abc123", "limit": 5}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 1);
}

// -- Paper References --

#[tokio::test]
async fn paper_references() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/paper/abc123/references"))
        .and(header("x-api-key", "test-api-key-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "offset": 0,
            "data": [
                {"citedPaper": {"paperId": "r1", "title": "Referenced Paper 1"}},
                {"citedPaper": {"paperId": "r2", "title": "Referenced Paper 2"}},
                {"citedPaper": {"paperId": "r3", "title": "Referenced Paper 3"}},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "semanticscholar.paper.references",
            "input": {"paper_id": "abc123"}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn paper_references_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/paper/abc123/references"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "semanticscholar.paper.references",
            "input": {"paper_id": "abc123"}
        }))
        .await
        .unwrap();
    assert!(result["data"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn paper_references_missing_paper_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "semanticscholar.paper.references",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Paper Recommendations --

#[tokio::test]
async fn paper_recommendations() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/paper/abc123/recommendations"))
        .and(header("x-api-key", "test-api-key-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "recommendedPapers": [
                {"paperId": "rec1", "title": "Recommended Paper 1"},
                {"paperId": "rec2", "title": "Recommended Paper 2"},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "semanticscholar.paper.recommendations",
            "input": {"paper_id": "abc123"}
        }))
        .await
        .unwrap();
    assert_eq!(result["recommendedPapers"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn paper_recommendations_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/paper/abc123/recommendations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "recommendedPapers": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "semanticscholar.paper.recommendations",
            "input": {"paper_id": "abc123"}
        }))
        .await
        .unwrap();
    assert!(result["recommendedPapers"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn paper_recommendations_missing_paper_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "semanticscholar.paper.recommendations",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// -- Author Get --

#[tokio::test]
async fn author_get() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/author/1741101"))
        .and(header("x-api-key", "test-api-key-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "authorId": "1741101",
            "name": "Yoshua Bengio",
            "hIndex": 200,
            "citationCount": 500000,
            "paperCount": 1000,
            "affiliations": ["Mila"],
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "semanticscholar.author.get",
            "input": {"author_id": "1741101"}
        }))
        .await
        .unwrap();
    assert_eq!(result["authorId"], "1741101");
    assert_eq!(result["name"], "Yoshua Bengio");
    assert_eq!(result["hIndex"], 200);
}

#[tokio::test]
async fn author_get_missing_author_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "semanticscholar.author.get",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn author_get_with_fields() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/author/1741101"))
        .and(query_param("fields", "name,hIndex"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "authorId": "1741101",
            "name": "Yoshua Bengio",
            "hIndex": 200,
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "semanticscholar.author.get",
            "input": {"author_id": "1741101", "fields": "name,hIndex"}
        }))
        .await
        .unwrap();
    assert_eq!(result["authorId"], "1741101");
}

// -- Author Papers --

#[tokio::test]
async fn author_papers() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/author/1741101/papers"))
        .and(header("x-api-key", "test-api-key-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "offset": 0,
            "data": [
                {"paperId": "p1", "title": "Paper One", "year": 2020},
                {"paperId": "p2", "title": "Paper Two", "year": 2021},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "semanticscholar.author.papers",
            "input": {"author_id": "1741101"}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn author_papers_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/author/1741101/papers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "semanticscholar.author.papers",
            "input": {"author_id": "1741101"}
        }))
        .await
        .unwrap();
    assert!(result["data"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn author_papers_missing_author_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "semanticscholar.author.papers",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn author_papers_with_limit() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/author/1741101/papers"))
        .and(query_param("limit", "10"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"paperId": "p1"}]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "semanticscholar.author.papers",
            "input": {"author_id": "1741101", "limit": 10}
        }))
        .await
        .unwrap();
    assert_eq!(result["data"].as_array().unwrap().len(), 1);
}

// -- Error handling --

#[tokio::test]
async fn error_401() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/paper/search"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(json!({"message": "Invalid API key"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "semanticscholar.paper.search",
            "input": {"query": "test"}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn error_403() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/paper/search"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_json(json!({"message": "Forbidden"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "semanticscholar.paper.search",
            "input": {"query": "test"}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn error_404() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/paper/nonexistent_id"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"message": "Paper not found"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "semanticscholar.paper.get",
            "input": {"paper_id": "nonexistent_id"}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/paper/search"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"message": "Rate limit exceeded"}))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "semanticscholar.paper.search",
            "input": {"query": "test"}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn error_500() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/author/1741101"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "semanticscholar.author.get",
            "input": {"author_id": "1741101"}
        }))
        .await
        .is_err()
    );
}

// -- Unknown op / Simulate --

#[tokio::test]
async fn unknown_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "semanticscholar.nope",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[tokio::test]
async fn simulate_known_paper_search() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "semanticscholar.paper.search"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[tokio::test]
async fn simulate_known_author_get() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "semanticscholar.author.get"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[tokio::test]
async fn simulate_unknown() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        !c.handle_simulate(json!({"operation_id": "semanticscholar.nope"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

// -- Counters --

#[tokio::test]
async fn counters_increment() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/paper/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 0,
            "data": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "semanticscholar.paper.search",
        "input": {"query": "test"}
    }))
    .await
    .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 0);
}

#[tokio::test]
async fn counters_error_increment() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/paper/search"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "semanticscholar.paper.search",
            "input": {"query": "test"}
        }))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}

// -- No auth (public API) --

#[tokio::test]
async fn paper_search_without_api_key() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/paper/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 5,
            "data": [{"paperId": "p1", "title": "Test"}]
        })))
        .mount(&server)
        .await;

    let c = setup_connector_no_key(&server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "semanticscholar.paper.search",
            "input": {"query": "test"}
        }))
        .await
        .unwrap();
    assert_eq!(result["total"], 5);
}

#[tokio::test]
async fn handshake_returns_protocol_info() {
    let server = MockServer::start().await;
    let mut c = SemanticScholarConnector::new();
    c.handle_configure(json!({ "base_url": server.uri() }))
        .await
        .unwrap();
    let hs = c
        .handle_handshake(json!({"session_id": "s1"}))
        .await
        .unwrap();
    assert_eq!(hs["protocol_version"], "2.0");
    assert_eq!(hs["connector_id"], "fcp.semanticscholar");
    assert_eq!(hs["connector_version"], "0.1.0");
    assert!(hs["capabilities"].as_array().unwrap().len() >= 2);
}
