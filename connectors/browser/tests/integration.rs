//! Browser connector integration tests.
//!
//! Deterministic integration tests using wiremock to mock the browser API.
//! No real browser connections. Covers:
//! - Happy-path operations (navigate, screenshot, extract, interact, cookies, proxy)
//! - Error taxonomy (429/500/400)
//! - FCP2 default-deny + capability verification
//! - Lifecycle (health, introspect, shutdown)
//! - Input validation (missing required fields)

#![allow(clippy::too_many_lines)]

use chrono::{Duration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_prelude::CapabilityConstraints;
use fcp_testkit::AsyncTestContext;
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

use fcp_browser::connector::BrowserConnector;

// ============================================================================
// Helpers
// ============================================================================

/// Generate a valid COSE capability token signed by the given key.
fn generate_valid_token(
    signing_key: &Ed25519SigningKey,
    connector: &BrowserConnector,
    op: &str,
) -> fcp_core::CapabilityToken {
    let now = Utc::now();
    let cap = match op {
        "browser.screenshot" | "browser.render_pdf" => "browser.capture",
        "browser.extract_text" | "browser.extract_links" | "browser.wait_for_selector" => {
            "browser.extract"
        }
        "browser.click" | "browser.fill_form" => "browser.interact",
        "browser.evaluate_js" => "browser.execute",
        "browser.get_cookies" | "browser.set_cookies" => "browser.cookies",
        "browser.session.save" | "browser.session.restore" | "browser.session.describe" => {
            "browser.sessions"
        }
        "browser.set_proxy" | "browser.clear_proxy" => "browser.proxy",
        "browser.navigate" => "browser.navigate",
        _ => op,
    };
    // C3.4: tokens MUST include constraints (default-deny)
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(cap)
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[op])
        .issuer("node:test")
        .target_instance(connector.instance_id())
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .unwrap();
    fcp_core::CapabilityToken::from_raw(cose)
}

/// Generate a valid execution-scope approval token for dangerous operations.
fn generate_execution_approval(
    operation: &str,
    _input: &serde_json::Value,
) -> fcp_core::ApprovalToken {
    generate_execution_approval_with_pattern(operation)
}

/// Generate a valid execution-scope approval token for a method pattern.
fn generate_execution_approval_with_pattern(method_pattern: &str) -> fcp_core::ApprovalToken {
    let now_ms = u64::try_from(Utc::now().timestamp_millis()).unwrap_or(0);
    fcp_core::ApprovalToken {
        token_id: format!("approval-{method_pattern}-{now_ms}"),
        issued_at_ms: now_ms.saturating_sub(1_000),
        expires_at_ms: now_ms + 300_000,
        issuer: "owner:test".into(),
        scope: fcp_core::ApprovalScope::Execution(fcp_core::ExecutionScope {
            connector_id: "fcp.browser".into(),
            method_pattern: method_pattern.into(),
            request_object_id: None,
            input_hash: None,
            input_constraints: vec![],
        }),
        zone_id: fcp_core::ZoneId::work(),
        signature: None,
    }
}

/// Perform handshake on a connector, returning the signing key for token generation.
async fn setup_handshake(connector: &mut BrowserConnector, caps: &[&str]) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let mapped_caps: Vec<&str> = caps
        .iter()
        .map(|&op| match op {
            "browser.screenshot" | "browser.render_pdf" => "browser.capture",
            "browser.extract_text" | "browser.extract_links" | "browser.wait_for_selector" => {
                "browser.extract"
            }
            "browser.click" | "browser.fill_form" => "browser.interact",
            "browser.evaluate_js" => "browser.execute",
            "browser.get_cookies" | "browser.set_cookies" => "browser.cookies",
            "browser.session.save" | "browser.session.restore" | "browser.session.describe" => {
                "browser.sessions"
            }
            "browser.set_proxy" | "browser.clear_proxy" => "browser.proxy",
            "browser.navigate" => "browser.navigate",
            _ => op,
        })
        .collect();

    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": mapped_caps
        }))
        .await
        .expect("handshake should succeed");

    signing_key
}

/// Configure connector with a mock server URL.
async fn setup_configure(connector: &mut BrowserConnector, base_url: &str) {
    connector
        .handle_configure(json!({
            "browser_url": base_url
        }))
        .await
        .expect("configure should succeed");
}

// ============================================================================
// Happy-path operation tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn test_navigate() {
    let _ctx = AsyncTestContext::for_scenario("browser-navigate");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/navigate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "url": "https://example.com",
            "status": 200,
            "title": "Example Domain"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = BrowserConnector::new();
    let key = setup_handshake(&mut connector, &["browser.navigate"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, &connector, "browser.navigate");
    let result = connector
        .handle_invoke(json!({
            "operation": "browser.navigate",
            "input": { "url": "https://example.com", "wait_until": "networkidle" },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["url"], "https://example.com");
    assert_eq!(result["status"], 200);
    assert_eq!(result["title"], "Example Domain");
}

#[fcp_async_core::runtime::test]
async fn test_screenshot() {
    let _ctx = AsyncTestContext::for_scenario("browser-screenshot");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/screenshot"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "image_data": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB...",
            "width": 1920,
            "height": 1080
        })))
        .mount(&mock_server)
        .await;

    let mut connector = BrowserConnector::new();
    let key = setup_handshake(&mut connector, &["browser.screenshot"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, &connector, "browser.screenshot");
    let result = connector
        .handle_invoke(json!({
            "operation": "browser.screenshot",
            "input": { "full_page": true, "format": "png" },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["width"], 1920);
    assert_eq!(result["height"], 1080);
    assert!(result["image_data"].as_str().unwrap().starts_with("iVBOR"));
}

#[fcp_async_core::runtime::test]
async fn test_render_pdf() {
    let _ctx = AsyncTestContext::for_scenario("browser-render-pdf");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/pdf"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "pdf_data": "JVBERi0xLjQK...",
            "page_count": 3
        })))
        .mount(&mock_server)
        .await;

    let mut connector = BrowserConnector::new();
    let key = setup_handshake(&mut connector, &["browser.render_pdf"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, &connector, "browser.render_pdf");
    let result = connector
        .handle_invoke(json!({
            "operation": "browser.render_pdf",
            "input": { "format": "a4", "landscape": true, "print_background": true },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["page_count"], 3);
    assert!(result["pdf_data"].as_str().unwrap().starts_with("JVBER"));
}

#[fcp_async_core::runtime::test]
async fn test_extract_text() {
    let _ctx = AsyncTestContext::for_scenario("browser-extract-text");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/extract_text"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "text": "Hello, world! This is example content.",
            "word_count": 6
        })))
        .mount(&mock_server)
        .await;

    let mut connector = BrowserConnector::new();
    let key = setup_handshake(&mut connector, &["browser.extract_text"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, &connector, "browser.extract_text");
    let result = connector
        .handle_invoke(json!({
            "operation": "browser.extract_text",
            "input": { "selector": "article" },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["text"], "Hello, world! This is example content.");
    assert_eq!(result["word_count"], 6);
}

#[fcp_async_core::runtime::test]
async fn test_extract_links() {
    let _ctx = AsyncTestContext::for_scenario("browser-extract-links");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/extract_links"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "links": [
                { "href": "https://example.com/about", "text": "About Us" },
                { "href": "https://example.com/contact", "text": "Contact" }
            ]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = BrowserConnector::new();
    let key = setup_handshake(&mut connector, &["browser.extract_links"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, &connector, "browser.extract_links");
    let result = connector
        .handle_invoke(json!({
            "operation": "browser.extract_links",
            "input": { "selector": "nav" },
            "capability_token": token
        }))
        .await
        .unwrap();

    let links = result["links"].as_array().unwrap();
    assert_eq!(links.len(), 2);
    assert_eq!(links[0]["href"], "https://example.com/about");
    assert_eq!(links[1]["text"], "Contact");
}

#[fcp_async_core::runtime::test]
async fn test_wait_for_selector() {
    let _ctx = AsyncTestContext::for_scenario("browser-wait-for-selector");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/wait_for_selector"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "found": true
        })))
        .mount(&mock_server)
        .await;

    let mut connector = BrowserConnector::new();
    let key = setup_handshake(&mut connector, &["browser.wait_for_selector"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, &connector, "browser.wait_for_selector");
    let result = connector
        .handle_invoke(json!({
            "operation": "browser.wait_for_selector",
            "input": { "selector": ".results-loaded", "timeout_ms": 5000 },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["found"], true);
}

#[fcp_async_core::runtime::test]
async fn test_click() {
    let _ctx = AsyncTestContext::for_scenario("browser-click");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/click"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "clicked": true,
            "navigation_url": "https://example.com/next-page"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = BrowserConnector::new();
    let key = setup_handshake(&mut connector, &["browser.click"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, &connector, "browser.click");
    let result = connector
        .handle_invoke(json!({
            "operation": "browser.click",
            "input": { "selector": "button.submit" },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["clicked"], true);
    assert_eq!(result["navigation_url"], "https://example.com/next-page");
}

#[fcp_async_core::runtime::test]
async fn test_fill_form() {
    let _ctx = AsyncTestContext::for_scenario("browser-fill-form");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/fill_form"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "filled_count": 3,
            "submitted": true
        })))
        .mount(&mock_server)
        .await;

    let mut connector = BrowserConnector::new();
    let key = setup_handshake(&mut connector, &["browser.fill_form"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, &connector, "browser.fill_form");
    let input = json!({
        "fields": {
            "#name": "Alice",
            "#email": "alice@example.com",
            "#message": "Hello!"
        },
        "submit_selector": "button[type=submit]"
    });
    let approval = generate_execution_approval("browser.fill_form", &input);
    let result = connector
        .handle_invoke(json!({
            "operation": "browser.fill_form",
            "input": input,
            "capability_token": token,
            "approval_token": approval
        }))
        .await
        .unwrap();

    assert_eq!(result["filled_count"], 3);
    assert_eq!(result["submitted"], true);
    assert_eq!(result["audit"]["operation"], "browser.fill_form");
    assert_eq!(result["audit"]["dangerous"], true);
}

#[fcp_async_core::runtime::test]
async fn test_evaluate_js() {
    let _ctx = AsyncTestContext::for_scenario("browser-evaluate-js");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/evaluate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "Example Domain"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = BrowserConnector::new();
    let key = setup_handshake(&mut connector, &["browser.evaluate_js"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, &connector, "browser.evaluate_js");
    let input = json!({ "expression": "document.title" });
    let approval = generate_execution_approval("browser.evaluate_js", &input);
    let result = connector
        .handle_invoke(json!({
            "operation": "browser.evaluate_js",
            "input": input,
            "capability_token": token,
            "approval_token": approval
        }))
        .await
        .unwrap();

    assert_eq!(result["result"], "Example Domain");
    assert_eq!(result["audit"]["operation"], "browser.evaluate_js");
    assert_eq!(result["audit"]["dangerous"], true);
}

#[fcp_async_core::runtime::test]
async fn test_get_cookies() {
    let _ctx = AsyncTestContext::for_scenario("browser-get-cookies");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/cookies"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cookies": [
                { "name": "session", "value": "abc123", "domain": "example.com" },
                { "name": "pref", "value": "dark", "domain": "example.com" }
            ]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = BrowserConnector::new();
    let key = setup_handshake(&mut connector, &["browser.get_cookies"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, &connector, "browser.get_cookies");
    let input = json!({ "domain": "example.com" });
    let approval = generate_execution_approval("browser.get_cookies", &input);
    let result = connector
        .handle_invoke(json!({
            "operation": "browser.get_cookies",
            "input": input,
            "capability_token": token,
            "approval_token": approval
        }))
        .await
        .unwrap();

    let cookies = result["cookies"].as_array().unwrap();
    assert_eq!(cookies.len(), 2);
    assert_eq!(cookies[0]["name"], "session");
    assert_eq!(cookies[1]["name"], "pref");
    assert_eq!(result["audit"]["operation"], "browser.get_cookies");
    assert_eq!(result["audit"]["dangerous"], true);
    assert_eq!(result["audit"]["side_effect"], false);
}

#[fcp_async_core::runtime::test]
async fn test_set_cookies() {
    let _ctx = AsyncTestContext::for_scenario("browser-set-cookies");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/set_cookies"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "set_count": 2
        })))
        .mount(&mock_server)
        .await;

    let mut connector = BrowserConnector::new();
    let key = setup_handshake(&mut connector, &["browser.set_cookies"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, &connector, "browser.set_cookies");
    let input = json!({
        "cookies": [
            { "name": "session", "value": "abc123", "domain": "example.com", "path": "/" },
            { "name": "pref", "value": "dark", "domain": "example.com", "path": "/" }
        ]
    });
    let approval = generate_execution_approval("browser.set_cookies", &input);
    let result = connector
        .handle_invoke(json!({
            "operation": "browser.set_cookies",
            "input": input,
            "capability_token": token,
            "approval_token": approval
        }))
        .await
        .unwrap();

    assert_eq!(result["set_count"], 2);
    assert_eq!(result["audit"]["operation"], "browser.set_cookies");
    assert_eq!(result["audit"]["dangerous"], true);
    assert_eq!(result["audit"]["side_effect"], true);
}

#[fcp_async_core::runtime::test]
async fn test_session_save() {
    let _ctx = AsyncTestContext::for_scenario("browser-session-save");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/cookies"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cookies": [
                { "name": "session", "value": "abc123", "domain": "example.com", "path": "/" },
                { "name": "pref", "value": "dark", "domain": "example.com", "path": "/" }
            ]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = BrowserConnector::new();
    let key = setup_handshake(&mut connector, &["browser.session.save"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, &connector, "browser.session.save");
    let input = json!({
        "domain": "example.com",
        "lease_seq": 10,
        "lease_object_id": "lease-obj-10"
    });
    let approval = generate_execution_approval("browser.session.save", &input);
    let result = connector
        .handle_invoke(json!({
            "operation": "browser.session.save",
            "input": input,
            "capability_token": token,
            "approval_token": approval
        }))
        .await
        .unwrap();

    assert!(result["state_object_id"].as_str().is_some());
    assert_eq!(result["seq"], 0);
    assert_eq!(result["lease_seq"], 10);
    assert_eq!(result["cookie_count"], 2);
    assert!(result["payload_cbor_size"].as_u64().unwrap() > 0);
    assert_eq!(result["audit"]["operation"], "browser.session.save");
}

#[fcp_async_core::runtime::test]
async fn test_session_restore_and_describe() {
    let _ctx = AsyncTestContext::for_scenario("browser-session-restore-describe");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/cookies"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cookies": [
                { "name": "session", "value": "abc123", "domain": "example.com", "path": "/" }
            ]
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/set_cookies"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "set_count": 1
        })))
        .mount(&mock_server)
        .await;

    let mut connector = BrowserConnector::new();
    let key = setup_handshake(
        &mut connector,
        &[
            "browser.session.save",
            "browser.session.restore",
            "browser.session.describe",
        ],
    )
    .await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let save_token = generate_valid_token(&key, &connector, "browser.session.save");
    let save_input = json!({
        "domain": "example.com",
        "lease_seq": 10,
        "lease_object_id": "lease-obj-10"
    });
    let save_approval = generate_execution_approval("browser.session.save", &save_input);
    let saved = connector
        .handle_invoke(json!({
            "operation": "browser.session.save",
            "input": save_input,
            "capability_token": save_token,
            "approval_token": save_approval
        }))
        .await
        .unwrap();
    let state_object_id = saved["state_object_id"].as_str().unwrap().to_string();

    let restore_token = generate_valid_token(&key, &connector, "browser.session.restore");
    let restore_input = json!({
        "state_object_id": state_object_id,
        "lease_seq": 11,
        "lease_object_id": "lease-obj-11"
    });
    let restore_approval = generate_execution_approval("browser.session.restore", &restore_input);
    let restored = connector
        .handle_invoke(json!({
            "operation": "browser.session.restore",
            "input": restore_input,
            "capability_token": restore_token,
            "approval_token": restore_approval
        }))
        .await
        .unwrap();

    assert_eq!(restored["restored_count"], 1);
    assert_eq!(restored["cookie_count"], 1);
    assert_eq!(restored["lease_seq"], 11);
    assert_eq!(restored["audit"]["operation"], "browser.session.restore");

    let describe_token = generate_valid_token(&key, &connector, "browser.session.describe");
    let described = connector
        .handle_invoke(json!({
            "operation": "browser.session.describe",
            "input": { "state_object_id": state_object_id },
            "capability_token": describe_token
        }))
        .await
        .unwrap();

    assert_eq!(described["cookie_count"], 1);
    assert_eq!(described["seq"], 0);
    assert_eq!(described["lease_seq"], 10);
    assert_eq!(described["is_head"], true);
    assert!(described["payload_cbor_size"].as_u64().unwrap() > 0);
}

#[fcp_async_core::runtime::test]
async fn test_session_restore_rejects_stale_lease_seq() {
    let _ctx = AsyncTestContext::for_scenario("browser-session-restore-stale-lease");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/cookies"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "cookies": [
                { "name": "session", "value": "abc123", "domain": "example.com", "path": "/" }
            ]
        })))
        .mount(&mock_server)
        .await;

    let mut connector = BrowserConnector::new();
    let key = setup_handshake(
        &mut connector,
        &["browser.session.save", "browser.session.restore"],
    )
    .await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let save_token = generate_valid_token(&key, &connector, "browser.session.save");
    let save_input = json!({
        "lease_seq": 5,
        "lease_object_id": "lease-obj-5"
    });
    let save_approval = generate_execution_approval("browser.session.save", &save_input);
    let saved = connector
        .handle_invoke(json!({
            "operation": "browser.session.save",
            "input": save_input,
            "capability_token": save_token,
            "approval_token": save_approval
        }))
        .await
        .unwrap();

    let restore_token = generate_valid_token(&key, &connector, "browser.session.restore");
    let restore_input = json!({
        "state_object_id": saved["state_object_id"],
        "lease_seq": 4,
        "lease_object_id": "lease-obj-4"
    });
    let restore_approval = generate_execution_approval("browser.session.restore", &restore_input);
    let result = connector
        .handle_invoke(json!({
            "operation": "browser.session.restore",
            "input": restore_input,
            "capability_token": restore_token,
            "approval_token": restore_approval
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::Conflict { message } => {
            assert!(message.contains("stale lease_seq"));
        }
        e => panic!("Expected Conflict, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn test_set_proxy() {
    let _ctx = AsyncTestContext::for_scenario("browser-set-proxy");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/proxy/set"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "enabled": true,
            "mode": "fixed_servers",
            "server": "http://proxy.example.com:8080"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = BrowserConnector::new();
    let key = setup_handshake(&mut connector, &["browser.set_proxy"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, &connector, "browser.set_proxy");
    let input = json!({
        "server": "http://proxy.example.com:8080",
        "bypass_list": ["localhost"]
    });
    let approval = generate_execution_approval("browser.set_proxy", &input);
    let result = connector
        .handle_invoke(json!({
            "operation": "browser.set_proxy",
            "input": input,
            "capability_token": token,
            "approval_token": approval
        }))
        .await
        .unwrap();

    assert_eq!(result["enabled"], true);
    assert_eq!(result["mode"], "fixed_servers");
    assert_eq!(result["server"], "http://proxy.example.com:8080");
    assert_eq!(result["audit"]["operation"], "browser.set_proxy");
}

#[fcp_async_core::runtime::test]
async fn test_clear_proxy() {
    let _ctx = AsyncTestContext::for_scenario("browser-clear-proxy");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/proxy/clear"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "enabled": false,
            "mode": "direct",
            "server": null
        })))
        .mount(&mock_server)
        .await;

    let mut connector = BrowserConnector::new();
    let key = setup_handshake(&mut connector, &["browser.clear_proxy"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, &connector, "browser.clear_proxy");
    let input = json!({});
    let approval = generate_execution_approval("browser.clear_proxy", &input);
    let result = connector
        .handle_invoke(json!({
            "operation": "browser.clear_proxy",
            "input": input,
            "capability_token": token,
            "approval_token": approval
        }))
        .await
        .unwrap();

    assert_eq!(result["enabled"], false);
    assert_eq!(result["mode"], "direct");
    assert_eq!(result["server"], serde_json::Value::Null);
    assert_eq!(result["audit"]["operation"], "browser.clear_proxy");
}

// ============================================================================
// Error taxonomy
// ============================================================================

#[fcp_async_core::runtime::test]
async fn test_error_429_rate_limited() {
    let _ctx = AsyncTestContext::for_scenario("browser-error-429");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/navigate"))
        .respond_with(ResponseTemplate::new(429))
        .mount(&mock_server)
        .await;

    let mut connector = BrowserConnector::new();
    let key = setup_handshake(&mut connector, &["browser.navigate"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, &connector, "browser.navigate");
    let result = connector
        .handle_invoke(json!({
            "operation": "browser.navigate",
            "input": { "url": "https://example.com" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::RateLimited { retry_after_ms, .. } => assert_eq!(retry_after_ms, 5_000),
        e => panic!("Expected RateLimited, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn test_error_500_server_error() {
    let _ctx = AsyncTestContext::for_scenario("browser-error-500");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/screenshot"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&mock_server)
        .await;

    let mut connector = BrowserConnector::new();
    let key = setup_handshake(&mut connector, &["browser.screenshot"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, &connector, "browser.screenshot");
    let result = connector
        .handle_invoke(json!({
            "operation": "browser.screenshot",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::External {
            retryable, service, ..
        } => {
            assert!(retryable);
            assert_eq!(service, "browser");
        }
        e => panic!("Expected External(retryable), got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn test_error_400_client_error() {
    let _ctx = AsyncTestContext::for_scenario("browser-error-400");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/click"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": { "message": "Element not found", "code": "element_not_found" }
        })))
        .mount(&mock_server)
        .await;

    let mut connector = BrowserConnector::new();
    let key = setup_handshake(&mut connector, &["browser.click"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, &connector, "browser.click");
    let result = connector
        .handle_invoke(json!({
            "operation": "browser.click",
            "input": { "selector": ".nonexistent" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::External {
            message, retryable, ..
        } => {
            assert!(!retryable);
            assert!(message.contains("Element not found"));
        }
        e => panic!("Expected External(not retryable), got: {e:?}"),
    }
}

// ============================================================================
// FCP2 default-deny
// ============================================================================

#[fcp_async_core::runtime::test]
async fn test_invoke_not_configured() {
    let _ctx = AsyncTestContext::for_scenario("browser-not-configured");

    let mut connector = BrowserConnector::new();
    let key = setup_handshake(&mut connector, &["browser.navigate"]).await;
    // Skip configure — connector not configured

    let token = generate_valid_token(&key, &connector, "browser.navigate");
    let result = connector
        .handle_invoke(json!({
            "operation": "browser.navigate",
            "input": { "url": "https://example.com" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        fcp_core::FcpError::NotConfigured
    ));
}

#[fcp_async_core::runtime::test]
async fn test_invoke_wrong_capability() {
    let _ctx = AsyncTestContext::for_scenario("browser-wrong-capability");
    let mock_server = MockServer::start().await;

    let mut connector = BrowserConnector::new();
    // Handshake with navigate capability only
    let key = setup_handshake(&mut connector, &["browser.navigate"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    // Try to invoke screenshot with a navigate token
    let token = generate_valid_token(&key, &connector, "browser.navigate");
    let result = connector
        .handle_invoke(json!({
            "operation": "browser.screenshot",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn test_dangerous_operation_requires_approval_token() {
    let _ctx = AsyncTestContext::for_scenario("browser-requires-execution-approval");
    let mock_server = MockServer::start().await;

    let mut connector = BrowserConnector::new();
    let key = setup_handshake(&mut connector, &["browser.evaluate_js"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, &connector, "browser.evaluate_js");
    let result = connector
        .handle_invoke(json!({
            "operation": "browser.evaluate_js",
            "input": { "expression": "document.title" },
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::CapabilityDenied { capability, reason } => {
            assert_eq!(capability, "browser.evaluate_js");
            assert!(reason.contains("ApprovalToken"));
        }
        e => panic!("Expected CapabilityDenied, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn test_all_execution_scoped_ops_require_approval_token() {
    let _ctx = AsyncTestContext::for_scenario("browser-all-execution-ops-require-approval");
    let mock_server = MockServer::start().await;

    let mut connector = BrowserConnector::new();
    let guarded_ops = [
        "browser.evaluate_js",
        "browser.fill_form",
        "browser.get_cookies",
        "browser.set_cookies",
        "browser.session.save",
        "browser.session.restore",
        "browser.set_proxy",
        "browser.clear_proxy",
    ];
    let key = setup_handshake(&mut connector, &guarded_ops).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let cases = [
        (
            "browser.evaluate_js",
            json!({ "expression": "document.title" }),
        ),
        (
            "browser.fill_form",
            json!({ "fields": { "#email": "test@example.com" } }),
        ),
        ("browser.get_cookies", json!({ "domain": "example.com" })),
        (
            "browser.set_cookies",
            json!({
                "cookies": [{ "name": "session", "value": "abc123", "domain": "example.com", "path": "/" }]
            }),
        ),
        (
            "browser.set_proxy",
            json!({ "server": "http://proxy.example.com:8080" }),
        ),
        (
            "browser.session.save",
            json!({ "lease_seq": 10, "lease_object_id": "lease-obj-10" }),
        ),
        (
            "browser.session.restore",
            json!({ "lease_seq": 10, "lease_object_id": "lease-obj-10" }),
        ),
        ("browser.clear_proxy", json!({})),
    ];

    for (operation, input) in cases {
        let token = generate_valid_token(&key, &connector, operation);
        let result = connector
            .handle_invoke(json!({
                "operation": operation,
                "input": input,
                "capability_token": token
            }))
            .await;

        assert!(
            result.is_err(),
            "operation should require approval: {operation}"
        );
        match result.unwrap_err() {
            fcp_core::FcpError::CapabilityDenied { capability, reason } => {
                assert_eq!(capability, operation);
                assert!(
                    reason.contains("ApprovalToken"),
                    "operation should mention ApprovalToken requirement: {operation}"
                );
            }
            e => panic!("Expected CapabilityDenied for {operation}, got: {e:?}"),
        }
    }
}

#[fcp_async_core::runtime::test]
async fn test_dangerous_operation_allows_wildcard_execution_scope() {
    let _ctx = AsyncTestContext::for_scenario("browser-approval-wildcard-pattern");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/evaluate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "Example Domain"
        })))
        .mount(&mock_server)
        .await;

    let mut connector = BrowserConnector::new();
    let key = setup_handshake(&mut connector, &["browser.evaluate_js"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, &connector, "browser.evaluate_js");
    let input = json!({ "expression": "document.title" });
    let approval = generate_execution_approval_with_pattern("browser.*");
    let result = connector
        .handle_invoke(json!({
            "operation": "browser.evaluate_js",
            "input": input,
            "capability_token": token,
            "approval_token": approval
        }))
        .await
        .unwrap();

    assert_eq!(result["result"], "Example Domain");
    assert_eq!(result["audit"]["operation"], "browser.evaluate_js");
    assert_eq!(result["audit"]["dangerous"], true);
}

#[fcp_async_core::runtime::test]
async fn test_dangerous_operation_approval_scope_mismatch() {
    let _ctx = AsyncTestContext::for_scenario("browser-approval-scope-mismatch");
    let mock_server = MockServer::start().await;

    let mut connector = BrowserConnector::new();
    let key = setup_handshake(&mut connector, &["browser.evaluate_js"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, &connector, "browser.evaluate_js");
    let approval = generate_execution_approval("browser.set_proxy", &json!({}));
    let result = connector
        .handle_invoke(json!({
            "operation": "browser.evaluate_js",
            "input": { "expression": "document.title" },
            "capability_token": token,
            "approval_token": approval
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::CapabilityDenied { capability, reason } => {
            assert_eq!(capability, "browser.evaluate_js");
            assert!(reason.contains("does not allow"));
        }
        e => panic!("Expected CapabilityDenied, got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn test_invoke_unknown_operation() {
    let _ctx = AsyncTestContext::for_scenario("browser-unknown-operation");
    let mock_server = MockServer::start().await;

    let mut connector = BrowserConnector::new();
    let key = setup_handshake(&mut connector, &["browser.nonexistent"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, &connector, "browser.nonexistent");
    let result = connector
        .handle_invoke(json!({
            "operation": "browser.nonexistent",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::OperationNotGranted { operation } => {
            assert_eq!(operation, "browser.nonexistent");
        }
        e => panic!("Expected OperationNotGranted, got: {e:?}"),
    }
}

// ============================================================================
// Lifecycle
// ============================================================================

#[fcp_async_core::runtime::test]
async fn test_health_not_configured() {
    let _ctx = AsyncTestContext::for_scenario("browser-health-not-configured");
    let connector = BrowserConnector::new();
    let result = connector.handle_health().await.unwrap();
    assert_eq!(result["status"], "not_configured");
}

#[fcp_async_core::runtime::test]
async fn test_health_configured() {
    let _ctx = AsyncTestContext::for_scenario("browser-health-configured");
    let mut connector = BrowserConnector::new();
    setup_configure(&mut connector, "http://localhost:9222").await;

    let result = connector.handle_health().await.unwrap();
    assert_eq!(result["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn test_introspect_operations() {
    let _ctx = AsyncTestContext::for_scenario("browser-introspect");
    let connector = BrowserConnector::new();
    let result = connector.handle_introspect().await.unwrap();

    let ops = result["operations"].as_array().unwrap();
    assert_eq!(ops.len(), 16);

    let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();
    assert!(op_ids.contains(&"browser.navigate"));
    assert!(op_ids.contains(&"browser.screenshot"));
    assert!(op_ids.contains(&"browser.render_pdf"));
    assert!(op_ids.contains(&"browser.extract_text"));
    assert!(op_ids.contains(&"browser.extract_links"));
    assert!(op_ids.contains(&"browser.wait_for_selector"));
    assert!(op_ids.contains(&"browser.click"));
    assert!(op_ids.contains(&"browser.fill_form"));
    assert!(op_ids.contains(&"browser.evaluate_js"));
    assert!(op_ids.contains(&"browser.get_cookies"));
    assert!(op_ids.contains(&"browser.set_cookies"));
    assert!(op_ids.contains(&"browser.session.save"));
    assert!(op_ids.contains(&"browser.session.restore"));
    assert!(op_ids.contains(&"browser.session.describe"));
    assert!(op_ids.contains(&"browser.set_proxy"));
    assert!(op_ids.contains(&"browser.clear_proxy"));
}

#[fcp_async_core::runtime::test]
async fn test_shutdown() {
    let _ctx = AsyncTestContext::for_scenario("browser-shutdown");
    let connector = BrowserConnector::new();
    let result = connector.handle_shutdown(json!({})).await.unwrap();
    assert_eq!(result["status"], "shutdown");
}

// ============================================================================
// Input validation
// ============================================================================

#[fcp_async_core::runtime::test]
async fn test_navigate_missing_url() {
    let _ctx = AsyncTestContext::for_scenario("browser-missing-url");
    let mock_server = MockServer::start().await;

    let mut connector = BrowserConnector::new();
    let key = setup_handshake(&mut connector, &["browser.navigate"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, &connector, "browser.navigate");
    let result = connector
        .handle_invoke(json!({
            "operation": "browser.navigate",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("url"));
        }
        e => panic!("Expected InvalidRequest about 'url', got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn test_click_missing_selector() {
    let _ctx = AsyncTestContext::for_scenario("browser-missing-selector");
    let mock_server = MockServer::start().await;

    let mut connector = BrowserConnector::new();
    let key = setup_handshake(&mut connector, &["browser.click"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, &connector, "browser.click");
    let result = connector
        .handle_invoke(json!({
            "operation": "browser.click",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("selector"));
        }
        e => panic!("Expected InvalidRequest about 'selector', got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn test_evaluate_js_missing_expression() {
    let _ctx = AsyncTestContext::for_scenario("browser-missing-expression");
    let mock_server = MockServer::start().await;

    let mut connector = BrowserConnector::new();
    let key = setup_handshake(&mut connector, &["browser.evaluate_js"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, &connector, "browser.evaluate_js");
    let approval = generate_execution_approval("browser.evaluate_js", &json!({}));
    let result = connector
        .handle_invoke(json!({
            "operation": "browser.evaluate_js",
            "input": {},
            "capability_token": token,
            "approval_token": approval
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("expression"));
        }
        e => panic!("Expected InvalidRequest about 'expression', got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn test_fill_form_missing_fields() {
    let _ctx = AsyncTestContext::for_scenario("browser-missing-fields");
    let mock_server = MockServer::start().await;

    let mut connector = BrowserConnector::new();
    let key = setup_handshake(&mut connector, &["browser.fill_form"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, &connector, "browser.fill_form");
    let approval = generate_execution_approval("browser.fill_form", &json!({}));
    let result = connector
        .handle_invoke(json!({
            "operation": "browser.fill_form",
            "input": {},
            "capability_token": token,
            "approval_token": approval
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("fields"));
        }
        e => panic!("Expected InvalidRequest about 'fields', got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn test_set_cookies_missing_cookies() {
    let _ctx = AsyncTestContext::for_scenario("browser-missing-cookies");
    let mock_server = MockServer::start().await;

    let mut connector = BrowserConnector::new();
    let key = setup_handshake(&mut connector, &["browser.set_cookies"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, &connector, "browser.set_cookies");
    let approval = generate_execution_approval("browser.set_cookies", &json!({}));
    let result = connector
        .handle_invoke(json!({
            "operation": "browser.set_cookies",
            "input": {},
            "capability_token": token,
            "approval_token": approval
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("cookies"));
        }
        e => panic!("Expected InvalidRequest about 'cookies', got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn test_session_save_missing_lease_fields() {
    let _ctx = AsyncTestContext::for_scenario("browser-session-save-missing-lease");
    let mock_server = MockServer::start().await;

    let mut connector = BrowserConnector::new();
    let key = setup_handshake(&mut connector, &["browser.session.save"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, &connector, "browser.session.save");
    let approval = generate_execution_approval("browser.session.save", &json!({}));
    let result = connector
        .handle_invoke(json!({
            "operation": "browser.session.save",
            "input": {},
            "capability_token": token,
            "approval_token": approval
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("lease_seq"));
        }
        e => panic!("Expected InvalidRequest about 'lease_seq', got: {e:?}"),
    }
}

#[fcp_async_core::runtime::test]
async fn test_wait_for_selector_missing_selector() {
    let _ctx = AsyncTestContext::for_scenario("browser-missing-wait-selector");
    let mock_server = MockServer::start().await;

    let mut connector = BrowserConnector::new();
    let key = setup_handshake(&mut connector, &["browser.wait_for_selector"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, &connector, "browser.wait_for_selector");
    let result = connector
        .handle_invoke(json!({
            "operation": "browser.wait_for_selector",
            "input": {},
            "capability_token": token
        }))
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        fcp_core::FcpError::InvalidRequest { message, .. } => {
            assert!(message.contains("selector"));
        }
        e => panic!("Expected InvalidRequest about 'selector', got: {e:?}"),
    }
}
