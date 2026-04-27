//! Integration tests for the FCP `arXiv` connector.

#![allow(
    clippy::cast_possible_truncation,
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use serde_json::json;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_arxiv::connector::ArxivConnector;

// ── Sample XML responses ────────────────────────────────────────────

fn sample_atom_feed() -> String {
    r#"<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
<opensearch:totalResults>2</opensearch:totalResults>
<entry>
<id>http://arxiv.org/abs/1706.03762v7</id>
<title>Attention Is All You Need</title>
<summary>The dominant sequence transduction models are based on complex recurrent or convolutional neural networks.</summary>
<author><name>Ashish Vaswani</name></author>
<author><name>Noam Shazeer</name></author>
<published>2017-06-12T17:57:34Z</published>
<updated>2023-08-02T01:04:45Z</updated>
<arxiv:primary_category term="cs.CL" scheme="http://arxiv.org/schemas/atom"/>
<category term="cs.CL"/>
<category term="cs.LG"/>
<link href="http://arxiv.org/pdf/1706.03762v7" rel="related" type="application/pdf"/>
</entry>
<entry>
<id>http://arxiv.org/abs/2301.08745v1</id>
<title>Another Paper</title>
<summary>This is another paper abstract.</summary>
<author><name>Alice Smith</name></author>
<published>2023-01-20T00:00:00Z</published>
<updated>2023-01-20T00:00:00Z</updated>
<arxiv:primary_category term="cs.AI" scheme="http://arxiv.org/schemas/atom"/>
<category term="cs.AI"/>
</entry>
</feed>"#
        .to_string()
}

fn sample_single_paper_feed() -> String {
    r#"<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
<opensearch:totalResults>1</opensearch:totalResults>
<entry>
<id>http://arxiv.org/abs/1706.03762v7</id>
<title>Attention Is All You Need</title>
<summary>The dominant sequence transduction models.</summary>
<author><name>Ashish Vaswani</name></author>
<published>2017-06-12T17:57:34Z</published>
<updated>2023-08-02T01:04:45Z</updated>
<arxiv:primary_category term="cs.CL" scheme="http://arxiv.org/schemas/atom"/>
<category term="cs.CL"/>
<arxiv:doi>10.48550/arXiv.1706.03762</arxiv:doi>
<arxiv:comment>15 pages, 5 figures</arxiv:comment>
</entry>
</feed>"#
        .to_string()
}

fn sample_empty_feed() -> String {
    r#"<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
<opensearch:totalResults>0</opensearch:totalResults>
</feed>"#
        .to_string()
}

// ── Helper ──────────────────────────────────────────────────────────

async fn setup_connector(arxiv_url: &str, scholar_url: &str) -> ArxivConnector {
    let mut c = ArxivConnector::new();
    c.handle_configure(json!({
        "arxiv_base_url": arxiv_url,
        "scholar_base_url": scholar_url,
    }))
    .await
    .unwrap();
    c.handle_handshake(json!({"session_id": "test"}))
        .await
        .unwrap();
    c
}

// ── Lifecycle ───────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured() {
    let c = ArxivConnector::new();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "unconfigured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_full() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri(), &server.uri()).await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_before_configure_fails() {
    let mut c = ArxivConnector::new();
    assert!(c.handle_handshake(json!({})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_shutdown() {
    let server = MockServer::start().await;
    let mut c = setup_connector(&server.uri(), &server.uri()).await;
    c.handle_shutdown(json!({})).await.unwrap();
    assert_eq!(c.handle_health().await.unwrap()["status"], "unconfigured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri(), &server.uri()).await;
    let check = c.handle_self_check().await.unwrap();
    assert_eq!(check["status"], "ok");
    assert!(
        check["details"]["provisioning"]["network_ok"]
            .as_bool()
            .unwrap()
    );
    assert!(
        check["details"]["provisioning"]["rate_limit_configured"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri(), &server.uri()).await;
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri(), &server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    assert_eq!(intro["operations"].as_array().unwrap().len(), 13);
}

#[fcp_async_core::runtime::test]
async fn lifecycle_configure_no_params() {
    let mut c = ArxivConnector::new();
    // arXiv connector accepts empty config (no auth required)
    c.handle_configure(json!({})).await.unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "degraded"); // configured but no handshake
}

#[fcp_async_core::runtime::test]
async fn lifecycle_configure_rejects_malicious_endpoints() {
    let mut c = ArxivConnector::new();
    let err = c
        .handle_configure(json!({
            "arxiv_base_url": "https://evil.example.com",
            "scholar_base_url": "https://evil.example.com",
            "scholar_api_key": "test-key",
        }))
        .await
        .unwrap_err();

    let rendered = err.to_string();
    assert!(rendered.contains("arxiv_base_url"));
    assert!(rendered.contains("export.arxiv.org"));

    let mut c = ArxivConnector::new();
    let err = c
        .handle_configure(json!({
            "arxiv_base_url": "https://export.arxiv.org",
            "scholar_base_url": "https://evil.example.com",
            "scholar_api_key": "test-key",
        }))
        .await
        .unwrap_err();

    let rendered = err.to_string();
    assert!(rendered.contains("scholar_base_url"));
    assert!(rendered.contains("scholar.google.com"));
}

// ── search_papers ───────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn search_papers() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/api/query.*"))
        .respond_with(ResponseTemplate::new(200).set_body_string(sample_atom_feed()))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri(), &server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "arxiv.search_papers",
            "input": {"query": "attention is all you need", "max_results": 10}
        }))
        .await
        .unwrap();
    assert_eq!(result["papers"].as_array().unwrap().len(), 2);
    assert_eq!(result["total_results"], 2);
}

#[fcp_async_core::runtime::test]
async fn search_papers_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/api/query.*"))
        .respond_with(ResponseTemplate::new(200).set_body_string(sample_empty_feed()))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri(), &server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "arxiv.search_papers",
            "input": {"query": "xyzzy_no_results"}
        }))
        .await
        .unwrap();
    assert!(result["papers"].as_array().unwrap().is_empty());
    assert_eq!(result["total_results"], 0);
}

#[fcp_async_core::runtime::test]
async fn search_papers_missing_query() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri(), &server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "arxiv.search_papers",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// ── search_semantic ─────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn search_semantic() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/paper/search.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 1,
            "data": [{
                "paperId": "p1",
                "title": "Test Paper",
                "year": 2023,
                "authors": [{"authorId": "a1", "name": "Alice"}]
            }]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri(), &server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "arxiv.search_semantic",
            "input": {"query": "graph neural networks for drug discovery"}
        }))
        .await
        .unwrap();
    assert_eq!(result["papers"].as_array().unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn search_semantic_missing_query() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri(), &server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "arxiv.search_semantic",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// ── get_paper ───────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn get_paper() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/api/query.*"))
        .respond_with(ResponseTemplate::new(200).set_body_string(sample_single_paper_feed()))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri(), &server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "arxiv.get_paper",
            "input": {"arxiv_id": "1706.03762"}
        }))
        .await
        .unwrap();
    assert_eq!(result["paper"]["title"], "Attention Is All You Need");
    assert_eq!(result["paper"]["arxiv_id"], "1706.03762v7");
}

#[fcp_async_core::runtime::test]
async fn get_paper_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/api/query.*"))
        .respond_with(ResponseTemplate::new(200).set_body_string(sample_empty_feed()))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri(), &server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "arxiv.get_paper",
            "input": {"arxiv_id": "0000.00000"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn get_paper_missing_id() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri(), &server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "arxiv.get_paper",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// ── get_full_text ───────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn get_full_text() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/e-print/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "\\documentclass{article}\n\\begin{document}\nHello world\n\\end{document}",
        ))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri(), &server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "arxiv.get_full_text",
            "input": {"arxiv_id": "1706.03762"}
        }))
        .await
        .unwrap();
    assert!(result["text"].as_str().unwrap().contains("Hello world"));
}

// ── download_pdf ────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn download_pdf() {
    let server = MockServer::start().await;
    let fake_pdf = b"%PDF-1.4 fake content";
    Mock::given(method("GET"))
        .and(path_regex("/pdf/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(fake_pdf.to_vec()))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri(), &server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "arxiv.download_pdf",
            "input": {"arxiv_id": "1706.03762"}
        }))
        .await
        .unwrap();
    assert!(!result["content"].as_str().unwrap().is_empty());
    assert!(result["size_bytes"].as_i64().unwrap() > 0);
}

// ── get_citations ───────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn get_citations() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/paper/ARXIV:.*/citations.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"citingPaper": {"paperId": "c1", "title": "Citing Paper 1"}},
                {"citingPaper": {"paperId": "c2", "title": "Citing Paper 2"}},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri(), &server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "arxiv.get_citations",
            "input": {"arxiv_id": "1706.03762", "max_results": 50}
        }))
        .await
        .unwrap();
    assert_eq!(result["citations"].as_array().unwrap().len(), 2);
    assert_eq!(result["total"], 2);
}

// ── get_references ──────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn get_references() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/paper/ARXIV:.*/references.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {"citedPaper": {"paperId": "r1", "title": "Referenced Paper 1", "year": 2015}},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri(), &server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "arxiv.get_references",
            "input": {"arxiv_id": "1706.03762"}
        }))
        .await
        .unwrap();
    assert_eq!(result["references"].as_array().unwrap().len(), 1);
}

// ── extract_references ──────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn extract_references() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/paper/ARXIV:.*/references.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [
                {
                    "citedPaper": {
                        "paperId": "r1",
                        "title": "Referenced Paper",
                        "year": 2015,
                        "authors": [{"authorId": "a1", "name": "Bob"}],
                        "externalIds": {"DOI": "10.1234/ref1"}
                    }
                },
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri(), &server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "arxiv.extract_references",
            "input": {"arxiv_id": "1706.03762"}
        }))
        .await
        .unwrap();
    let refs = result["references"].as_array().unwrap();
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0]["title"], "Referenced Paper");
    assert_eq!(refs[0]["year"], 2015);
}

// ── get_author ──────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn get_author() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/author/search.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 1,
            "data": [{
                "authorId": "12345",
                "name": "Ashish Vaswani",
                "paperCount": 50,
                "citationCount": 100000,
                "hIndex": 30,
                "papers": [
                    {"paperId": "p1", "title": "Attention Is All You Need", "year": 2017},
                ]
            }]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri(), &server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "arxiv.get_author",
            "input": {"author_name": "Ashish Vaswani", "max_papers": 50}
        }))
        .await
        .unwrap();
    assert_eq!(result["author"]["name"], "Ashish Vaswani");
    assert_eq!(result["papers"].as_array().unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn get_author_missing_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri(), &server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "arxiv.get_author",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// ── list_categories ─────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn list_categories_all() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri(), &server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "arxiv.list_categories",
            "input": {}
        }))
        .await
        .unwrap();
    let cats = result["categories"].as_array().unwrap();
    assert!(cats.len() > 100);
}

#[fcp_async_core::runtime::test]
async fn list_categories_filtered() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri(), &server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "arxiv.list_categories",
            "input": {"group": "cs"}
        }))
        .await
        .unwrap();
    let cats = result["categories"].as_array().unwrap();
    assert!(cats.len() > 30);
    for cat in cats {
        assert_eq!(cat["group"], "cs");
    }
}

#[fcp_async_core::runtime::test]
async fn list_categories_unknown_group() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri(), &server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "arxiv.list_categories",
            "input": {"group": "nonexistent"}
        }))
        .await
        .unwrap();
    assert!(result["categories"].as_array().unwrap().is_empty());
}

// ── get_new_papers ──────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn get_new_papers() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/api/query.*"))
        .respond_with(ResponseTemplate::new(200).set_body_string(sample_atom_feed()))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri(), &server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "arxiv.get_new_papers",
            "input": {"category": "cs.AI", "max_results": 25}
        }))
        .await
        .unwrap();
    assert_eq!(result["papers"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn get_new_papers_missing_category() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri(), &server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "arxiv.get_new_papers",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// ── monitor_category ────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn monitor_category() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/api/query.*"))
        .respond_with(ResponseTemplate::new(200).set_body_string(sample_atom_feed()))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri(), &server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "arxiv.monitor_category",
            "input": {"categories": ["cs.AI", "cs.CL"]}
        }))
        .await
        .unwrap();
    assert!(!result["papers"].as_array().unwrap().is_empty());
    assert!(!result["cursor_ts"].as_str().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn monitor_category_with_keyword() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/api/query.*"))
        .respond_with(ResponseTemplate::new(200).set_body_string(sample_atom_feed()))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri(), &server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "arxiv.monitor_category",
            "input": {
                "categories": ["cs.CL"],
                "keyword_filter": "attention"
            }
        }))
        .await
        .unwrap();
    // Should find papers matching "attention" keyword
    let papers = result["papers"].as_array().unwrap();
    for p in papers {
        let title = p["title"].as_str().unwrap().to_lowercase();
        let summary = p["summary"].as_str().unwrap().to_lowercase();
        assert!(title.contains("attention") || summary.contains("attention"));
    }
}

#[fcp_async_core::runtime::test]
async fn monitor_category_missing_categories() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri(), &server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "arxiv.monitor_category",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// ── monitor_query ───────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn monitor_query() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/api/query.*"))
        .respond_with(ResponseTemplate::new(200).set_body_string(sample_atom_feed()))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri(), &server.uri()).await;
    let result = c
        .handle_invoke(json!({
            "operation_id": "arxiv.monitor_query",
            "input": {"query": "ti:transformer AND cat:cs.CL"}
        }))
        .await
        .unwrap();
    assert!(!result["papers"].as_array().unwrap().is_empty());
    assert!(!result["cursor_ts"].as_str().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn monitor_query_missing_query() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri(), &server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "arxiv.monitor_query",
            "input": {}
        }))
        .await
        .is_err()
    );
}

// ── Error handling ──────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn error_arxiv_500() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/api/query.*"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri(), &server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "arxiv.search_papers",
            "input": {"query": "test"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_arxiv_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/api/query.*"))
        .respond_with(ResponseTemplate::new(429).set_body_string("Rate limited"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri(), &server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "arxiv.search_papers",
            "input": {"query": "test"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_scholar_404() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/paper/ARXIV:.*/citations.*"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"error": "Not Found", "message": "Paper not found"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri(), &server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "arxiv.get_citations",
            "input": {"arxiv_id": "0000.00000"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_scholar_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/paper/search.*"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(json!({"message": "Too many requests"}))
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri(), &server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "arxiv.search_semantic",
            "input": {"query": "test"}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_scholar_500() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/author/search.*"))
        .respond_with(
            ResponseTemplate::new(500).set_body_json(json!({"message": "Internal Server Error"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri(), &server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "arxiv.get_author",
            "input": {"author_name": "Alice"}
        }))
        .await
        .is_err()
    );
}

// ── Unknown op / Simulate ───────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn unknown_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri(), &server.uri()).await;
    assert!(
        c.handle_invoke(json!({
            "operation_id": "arxiv.nope",
            "input": {}
        }))
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri(), &server.uri()).await;
    assert!(
        c.handle_simulate(json!({
            "operation_id": "arxiv.search_papers",
            "input": {"query": "attention"},
        }))
        .await
        .unwrap()["allowed"]
        .as_bool()
        .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_unknown() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri(), &server.uri()).await;
    assert!(
        !c.handle_simulate(json!({"operation_id": "arxiv.nope"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_all_operations() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri(), &server.uri()).await;
    let ops = [
        ("arxiv.search_papers", json!({"query": "attention"})),
        ("arxiv.search_semantic", json!({"query": "attention"})),
        ("arxiv.get_paper", json!({"arxiv_id": "1706.03762"})),
        ("arxiv.get_full_text", json!({"arxiv_id": "1706.03762"})),
        ("arxiv.download_pdf", json!({"arxiv_id": "1706.03762"})),
        ("arxiv.get_citations", json!({"arxiv_id": "1706.03762"})),
        ("arxiv.get_references", json!({"arxiv_id": "1706.03762"})),
        ("arxiv.extract_references", json!({"arxiv_id": "1706.03762"})),
        ("arxiv.get_author", json!({"author_name": "Alice"})),
        ("arxiv.list_categories", json!({})),
        ("arxiv.get_new_papers", json!({"category": "cs.AI"})),
        ("arxiv.monitor_category", json!({"categories": ["cs.AI"]})),
        ("arxiv.monitor_query", json!({"query": "attention"})),
    ];
    for (op, input) in &ops {
        let result = c
            .handle_simulate(json!({
                "operation_id": op,
                "input": input,
            }))
            .await
            .unwrap();
        assert!(result["allowed"].as_bool().unwrap(), "op {op} not allowed");
    }
}

// ── Counters ────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn counters_increment() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/api/query.*"))
        .respond_with(ResponseTemplate::new(200).set_body_string(sample_atom_feed()))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri(), &server.uri()).await;
    c.handle_invoke(json!({
        "operation_id": "arxiv.search_papers",
        "input": {"query": "test"}
    }))
    .await
    .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 0);
}

#[fcp_async_core::runtime::test]
async fn counters_error_increment() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("/api/query.*"))
        .respond_with(ResponseTemplate::new(500).set_body_string("error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri(), &server.uri()).await;
    let _ = c
        .handle_invoke(json!({
            "operation_id": "arxiv.search_papers",
            "input": {"query": "test"}
        }))
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}
