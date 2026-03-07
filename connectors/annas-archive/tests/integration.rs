use serde_json::json;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_annas_archive::client::AnnasArchiveClient;
use fcp_annas_archive::connector::AnnasArchiveConnector;

// -- Client integration tests --

#[fcp_async_core::runtime::test]
async fn client_search_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .and(query_param("q", "machine learning"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [
                {
                    "md5": "abc123",
                    "title": "Machine Learning",
                    "author": "Author A",
                    "year": "2023",
                    "extension": "pdf",
                    "filesize": 5_000_000
                }
            ]
        })))
        .mount(&server)
        .await;

    let client = AnnasArchiveClient::new(Some(&server.uri())).unwrap();
    let result = client
        .search("machine learning", None, None, None)
        .await
        .unwrap();
    assert!(result["results"].is_array());
    assert_eq!(result["results"][0]["md5"], "abc123");
}

#[fcp_async_core::runtime::test]
async fn client_search_with_filters() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .and(query_param("q", "rust"))
        .and(query_param("lang", "en"))
        .and(query_param("ext", "pdf"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{"md5": "def456", "title": "Rust Programming"}]
        })))
        .mount(&server)
        .await;

    let client = AnnasArchiveClient::new(Some(&server.uri())).unwrap();
    let result = client
        .search("rust", Some("en"), Some("pdf"), None)
        .await
        .unwrap();
    assert_eq!(result["results"][0]["title"], "Rust Programming");
}

#[fcp_async_core::runtime::test]
async fn client_search_with_sort() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .and(query_param("q", "ai"))
        .and(query_param("sort", "newest"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": []
        })))
        .mount(&server)
        .await;

    let client = AnnasArchiveClient::new(Some(&server.uri())).unwrap();
    let result = client
        .search("ai", None, None, Some("newest"))
        .await
        .unwrap();
    assert!(result["results"].is_array());
}

#[fcp_async_core::runtime::test]
async fn client_get_metadata_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/md5/abc123def456"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "md5": "abc123def456",
            "title": "Test Book",
            "author": "Author",
            "isbn": "9780134685991",
            "description": "A test book"
        })))
        .mount(&server)
        .await;

    let client = AnnasArchiveClient::new(Some(&server.uri())).unwrap();
    let result = client.get_metadata("abc123def456").await.unwrap();
    assert_eq!(result["isbn"], "9780134685991");
}

#[fcp_async_core::runtime::test]
async fn client_lookup_isbn_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/isbn/9780134685991"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [{"md5": "abc", "title": "Clean Architecture"}]
        })))
        .mount(&server)
        .await;

    let client = AnnasArchiveClient::new(Some(&server.uri())).unwrap();
    let result = client.lookup_isbn("9780134685991").await.unwrap();
    assert!(result["results"].is_array());
    assert_eq!(result["results"][0]["title"], "Clean Architecture");
}

#[fcp_async_core::runtime::test]
async fn client_lookup_md5_success() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/md5/aabbccdd11223344"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "md5": "aabbccdd11223344",
            "title": "Found Book"
        })))
        .mount(&server)
        .await;

    let client = AnnasArchiveClient::new(Some(&server.uri())).unwrap();
    let result = client.lookup_md5("aabbccdd11223344").await.unwrap();
    assert_eq!(result["title"], "Found Book");
}

#[fcp_async_core::runtime::test]
async fn client_404_returns_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/md5/nonexistent"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": "Not found"
        })))
        .mount(&server)
        .await;

    let client = AnnasArchiveClient::new(Some(&server.uri())).unwrap();
    let err = client.get_metadata("nonexistent").await.unwrap_err();
    assert!(!err.is_retryable());
}

#[fcp_async_core::runtime::test]
async fn client_429_returns_rate_limited() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "30")
                .set_body_json(json!({"error": "Rate limited"})),
        )
        .mount(&server)
        .await;

    let client = AnnasArchiveClient::new(Some(&server.uri())).unwrap();
    let err = client.search("test", None, None, None).await.unwrap_err();
    assert!(err.is_retryable());
    assert!(err.retry_after().is_some());
}

#[fcp_async_core::runtime::test]
async fn client_503_returns_unavailable() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let client = AnnasArchiveClient::new(Some(&server.uri())).unwrap();
    let err = client.search("test", None, None, None).await.unwrap_err();
    assert!(err.is_retryable());
}

#[fcp_async_core::runtime::test]
async fn client_500_returns_api_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .respond_with(
            ResponseTemplate::new(500).set_body_json(json!({"message": "Internal error"})),
        )
        .mount(&server)
        .await;

    let client = AnnasArchiveClient::new(Some(&server.uri())).unwrap();
    let err = client.search("test", None, None, None).await.unwrap_err();
    assert!(!err.is_retryable());
}

#[fcp_async_core::runtime::test]
async fn client_empty_response_returns_empty_json() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .respond_with(ResponseTemplate::new(200).set_body_string(""))
        .mount(&server)
        .await;

    let client = AnnasArchiveClient::new(Some(&server.uri())).unwrap();
    let result = client.search("test", None, None, None).await.unwrap();
    assert_eq!(result, json!({}));
}

#[fcp_async_core::runtime::test]
async fn client_search_multiple_results() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [
                {"md5": "aaa", "title": "Book 1"},
                {"md5": "bbb", "title": "Book 2"},
                {"md5": "ccc", "title": "Book 3"},
            ]
        })))
        .mount(&server)
        .await;

    let client = AnnasArchiveClient::new(Some(&server.uri())).unwrap();
    let result = client.search("books", None, None, None).await.unwrap();
    assert_eq!(result["results"].as_array().unwrap().len(), 3);
}

// -- Connector lifecycle integration tests --

#[fcp_async_core::runtime::test]
async fn connector_configure() {
    let mut c = AnnasArchiveConnector::new();
    let resp = c.handle_configure(json!({})).await.unwrap();
    assert_eq!(resp, json!({}));
}

#[fcp_async_core::runtime::test]
async fn connector_handshake() {
    let mut c = AnnasArchiveConnector::new();
    c.handle_configure(json!({})).await.unwrap();
    let resp = c.handle_handshake(json!({})).await.unwrap();
    assert_eq!(resp["connector_id"], "fcp.annas-archive");
}

#[fcp_async_core::runtime::test]
async fn connector_health() {
    let c = AnnasArchiveConnector::new();
    let resp = c.handle_health().await.unwrap();
    assert!(resp["status"].is_string());
}

#[fcp_async_core::runtime::test]
async fn connector_doctor() {
    let c = AnnasArchiveConnector::new();
    let resp = c.handle_doctor().await.unwrap();
    assert!(resp["checks"].is_array());
}

#[fcp_async_core::runtime::test]
async fn connector_self_check() {
    let c = AnnasArchiveConnector::new();
    let resp = c.handle_self_check().await.unwrap();
    assert_eq!(resp["connector_id"], "fcp.annas-archive");
}

#[fcp_async_core::runtime::test]
async fn connector_introspect() {
    let c = AnnasArchiveConnector::new();
    let resp = c.handle_introspect().await.unwrap();
    assert_eq!(resp["operations"].as_array().unwrap().len(), 4);
}

#[fcp_async_core::runtime::test]
async fn connector_simulate_search() {
    let c = AnnasArchiveConnector::new();
    let resp = c
        .handle_simulate(json!({"operation_id": "annas.search"}))
        .await
        .unwrap();
    assert_eq!(resp["allowed"], true);
}

#[fcp_async_core::runtime::test]
async fn connector_simulate_metadata() {
    let c = AnnasArchiveConnector::new();
    let resp = c
        .handle_simulate(json!({"operation_id": "annas.metadata"}))
        .await
        .unwrap();
    assert_eq!(resp["allowed"], true);
}

#[fcp_async_core::runtime::test]
async fn connector_simulate_isbn() {
    let c = AnnasArchiveConnector::new();
    let resp = c
        .handle_simulate(json!({"operation_id": "annas.lookup.isbn"}))
        .await
        .unwrap();
    assert_eq!(resp["allowed"], true);
}

#[fcp_async_core::runtime::test]
async fn connector_simulate_md5() {
    let c = AnnasArchiveConnector::new();
    let resp = c
        .handle_simulate(json!({"operation_id": "annas.lookup.md5"}))
        .await
        .unwrap();
    assert_eq!(resp["allowed"], true);
}

#[fcp_async_core::runtime::test]
async fn connector_simulate_unknown() {
    let c = AnnasArchiveConnector::new();
    let resp = c
        .handle_simulate(json!({"operation_id": "annas.nonexistent"}))
        .await
        .unwrap();
    assert_eq!(resp["allowed"], false);
}

#[fcp_async_core::runtime::test]
async fn connector_shutdown() {
    let mut c = AnnasArchiveConnector::new();
    c.handle_configure(json!({})).await.unwrap();
    let resp = c.handle_shutdown(json!({})).await.unwrap();
    assert_eq!(resp, json!({}));
}

#[fcp_async_core::runtime::test]
async fn connector_invoke_requires_ready() {
    let c = AnnasArchiveConnector::new();
    let err = c
        .handle_invoke(json!({"operation_id": "annas.search", "input": {"query": "test"}}))
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        fcp_core::FcpError::NotConfigured | fcp_core::FcpError::NotHandshaken
    ));
}

#[fcp_async_core::runtime::test]
async fn connector_invoke_unknown_op() {
    let mut c = AnnasArchiveConnector::new();
    c.handle_configure(json!({})).await.unwrap();
    c.handle_handshake(json!({})).await.unwrap();
    let err = c
        .handle_invoke(json!({"operation_id": "annas.nonexistent", "input": {}}))
        .await
        .unwrap_err();
    assert!(matches!(err, fcp_core::FcpError::InvalidRequest { .. }));
}

#[fcp_async_core::runtime::test]
async fn connector_full_lifecycle() {
    let mut c = AnnasArchiveConnector::new();

    // Configure
    c.handle_configure(json!({})).await.unwrap();

    // Handshake
    let hs = c.handle_handshake(json!({})).await.unwrap();
    assert_eq!(hs["connector_id"], "fcp.annas-archive");

    // Health
    let health = c.handle_health().await.unwrap();
    assert_eq!(health["status"], "healthy");

    // Doctor
    let doctor = c.handle_doctor().await.unwrap();
    assert!(doctor["checks"].is_array());

    // Introspect
    let intro = c.handle_introspect().await.unwrap();
    assert_eq!(intro["operations"].as_array().unwrap().len(), 4);

    // Shutdown
    c.handle_shutdown(json!({})).await.unwrap();

    // Verify shutdown state
    let health_after = c.handle_health().await.unwrap();
    assert_eq!(health_after["status"], "unconfigured");
}

// -- Manifest validation --

#[test]
fn manifest_parses() {
    let manifest_str =
        std::fs::read_to_string("manifest.toml").expect("manifest.toml should exist");
    let parsed: toml::Value = toml::from_str(&manifest_str).expect("manifest should parse");
    assert_eq!(
        parsed["connector"]["id"].as_str().unwrap(),
        "fcp.annas-archive"
    );
    assert_eq!(
        parsed["connector"]["archetypes"][0].as_str().unwrap(),
        "knowledge"
    );
}

#[test]
fn manifest_operations_match_connector() {
    let manifest_str = std::fs::read_to_string("manifest.toml").unwrap();
    let parsed: toml::Value = toml::from_str(&manifest_str).unwrap();
    let ops = parsed["provides"]["operations"]
        .as_table()
        .expect("operations table");
    assert!(ops.contains_key("annas.search"));
    assert!(ops.contains_key("annas.metadata"));
    assert!(ops.contains_key("annas.lookup.isbn"));
    assert!(ops.contains_key("annas.lookup.md5"));
    assert_eq!(ops.len(), 4);
}

#[test]
fn manifest_rate_limit_pools() {
    let manifest_str = std::fs::read_to_string("manifest.toml").unwrap();
    let parsed: toml::Value = toml::from_str(&manifest_str).unwrap();
    let pools = parsed["rate_limits"]["pools"].as_array().unwrap();
    assert_eq!(pools.len(), 2);

    let pool_ids: Vec<&str> = pools.iter().map(|p| p["id"].as_str().unwrap()).collect();
    assert!(pool_ids.contains(&"annas.search"));
    assert!(pool_ids.contains(&"annas.read"));
}

#[test]
fn manifest_network_constraints_present() {
    let manifest_str = std::fs::read_to_string("manifest.toml").unwrap();
    let parsed: toml::Value = toml::from_str(&manifest_str).unwrap();
    let ops = parsed["provides"]["operations"].as_table().unwrap();
    for (name, op) in ops {
        let nc = op
            .get("network_constraints")
            .unwrap_or_else(|| panic!("{name} missing network_constraints"));
        let hosts = nc["host_allow"].as_array().unwrap();
        assert!(!hosts.is_empty(), "{name} has empty host_allow");
        assert!(
            nc["deny_localhost"].as_bool().unwrap(),
            "{name} must deny localhost"
        );
    }
}

#[test]
fn manifest_all_ops_safe() {
    let manifest_str = std::fs::read_to_string("manifest.toml").unwrap();
    let parsed: toml::Value = toml::from_str(&manifest_str).unwrap();
    let ops = parsed["provides"]["operations"].as_table().unwrap();
    for (name, op) in ops {
        assert_eq!(
            op["safety_tier"].as_str().unwrap(),
            "safe",
            "{name} should be safe"
        );
        assert_eq!(
            op["risk_level"].as_str().unwrap(),
            "low",
            "{name} should be low risk"
        );
    }
}

#[test]
fn manifest_stateless() {
    let manifest_str = std::fs::read_to_string("manifest.toml").unwrap();
    let parsed: toml::Value = toml::from_str(&manifest_str).unwrap();
    assert_eq!(
        parsed["connector"]["state"]["model"].as_str().unwrap(),
        "stateless"
    );
}
