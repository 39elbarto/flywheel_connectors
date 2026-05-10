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

use std::time::Instant;

use chrono::{Duration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_prelude::CapabilityConstraints;
use fcp_testkit::{AsyncTestContext, LogCapture};
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

use fcp_browser::client::BrowserClient;
use fcp_browser::connector::BrowserConnector;
use fcp_browser::types::ProxyConfig;

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

async fn browser_control_contract_response() -> serde_json::Value {
    BrowserConnector::new()
        .handle_health()
        .await
        .expect("browser health should serialize")
        .get("browser_control_contract")
        .cloned()
        .expect("health should include browser control contract")
}

async fn mount_browser_control_health(mock_server: &MockServer) {
    mount_browser_control_health_body(mock_server, browser_control_contract_response().await).await;
}

async fn mount_browser_control_health_body(mock_server: &MockServer, body: serde_json::Value) {
    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(mock_server)
        .await;
}

async fn browser_control_contract_without_proxy_operations() -> serde_json::Value {
    let mut descriptor = browser_control_contract_response().await;
    descriptor["operations"]
        .as_array_mut()
        .expect("contract operations should be an array")
        .retain(|operation| {
            !matches!(
                operation.get("id").and_then(serde_json::Value::as_str),
                Some("browser.set_proxy" | "browser.clear_proxy")
            )
        });
    descriptor
}

async fn browser_control_contract_with_invalid_proxy_policy() -> serde_json::Value {
    let mut descriptor = browser_control_contract_response().await;
    let set_proxy = descriptor["operations"]
        .as_array_mut()
        .expect("contract operations should be an array")
        .iter_mut()
        .find(|operation| operation["id"] == "browser.set_proxy")
        .expect("contract should include browser.set_proxy");
    set_proxy["implementation"]
        .as_object_mut()
        .expect("proxy implementation should be an object")
        .remove("redaction_contract");
    descriptor
}

fn advertised_worker_operations(contract: &serde_json::Value) -> Vec<String> {
    contract["operations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|operation| operation.get("id").and_then(serde_json::Value::as_str))
        .map(str::to_string)
        .collect()
}

fn proxy_descriptor_hash(input: &serde_json::Value) -> String {
    let bytes = serde_json::to_vec(input).expect("proxy descriptor should serialize");
    let digest = blake3::hash(&bytes);
    format!(
        "blake3:{}",
        digest.to_hex().chars().take(16).collect::<String>()
    )
}

fn proxy_proof_git_revision() -> &'static str {
    option_env!("GIT_COMMIT")
        .or(option_env!("VERGEN_GIT_SHA"))
        .unwrap_or("unknown")
}

fn emit_proxy_control_evidence(run_id: &str, scenario: &str, mut evidence: serde_json::Value) {
    let object = evidence
        .as_object_mut()
        .expect("proxy evidence should be a JSON object");
    object.insert(
        "schema_version".to_string(),
        json!("fcp-browser-proxy-control-mode-evidence.v1"),
    );
    object.insert("run_id".to_string(), json!(run_id));
    object.insert("scenario".to_string(), json!(scenario));
    object.insert(
        "command_line".to_string(),
        json!(
            "cargo test -p fcp-browser --test integration test_browser_proxy_control_mode_e2e_jsonl -- --nocapture"
        ),
    );
    object.insert(
        "git_revision".to_string(),
        json!(proxy_proof_git_revision()),
    );
    object.insert(
        "redaction".to_string(),
        json!({
            "raw_proxy_descriptor_logged": false,
            "raw_cdp_endpoint_logged": false,
            "proxy_descriptor_hash_only": true
        }),
    );
    println!("BROWSER_PROXY_CONTROL_MODE_JSONL {evidence}");
}

#[derive(Debug, Clone, Copy)]
struct BrowserE2eRouteExpectation {
    connector_operation: &'static str,
    worker_operation: &'static str,
    path: &'static str,
    target_id: &'static str,
    approval_required: bool,
}

async fn mount_full_flow_browser_control(mock_server: &MockServer) {
    mount_browser_control_health(mock_server).await;

    for (route, body) in [
        (
            "/navigate",
            json!({
                "url": "https://example.com/dashboard",
                "status": 200,
                "title": "Dashboard",
                "target_id": "target-nav-1"
            }),
        ),
        (
            "/screenshot",
            json!({
                "image_data": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB",
                "width": 1280,
                "height": 720,
                "target_id": "target-capture-1"
            }),
        ),
        (
            "/pdf",
            json!({
                "pdf_data": "JVBERi0xLjQKJcTl8uXr",
                "page_count": 2,
                "target_id": "target-pdf-1"
            }),
        ),
        (
            "/extract_text",
            json!({
                "text": "Dashboard Ready",
                "word_count": 2,
                "target_id": "target-text-1"
            }),
        ),
        (
            "/extract_links",
            json!({
                "links": [
                    { "href": "https://example.com/settings", "text": "Settings" }
                ],
                "target_id": "target-links-1"
            }),
        ),
        (
            "/wait_for_selector",
            json!({ "found": true, "target_id": "target-wait-1" }),
        ),
        (
            "/click",
            json!({
                "clicked": true,
                "navigation_url": "https://example.com/dashboard/next",
                "target_id": "target-click-1"
            }),
        ),
        (
            "/fill_form",
            json!({ "filled_count": 2, "submitted": true, "target_id": "target-fill-1" }),
        ),
        (
            "/evaluate",
            json!({ "result": "ready", "target_id": "target-evaluate-1" }),
        ),
        (
            "/cookies",
            json!({
                "cookies": [
                    { "name": "session", "value": "abc123", "domain": "example.com", "path": "/" },
                    { "name": "pref", "value": "dark", "domain": "example.com", "path": "/" }
                ],
                "target_id": "target-cookies-1"
            }),
        ),
        (
            "/set_cookies",
            json!({ "set_count": 2, "target_id": "target-set-cookies-1" }),
        ),
        (
            "/proxy/set",
            json!({
                "enabled": true,
                "mode": "fixed_servers",
                "server": "http://proxy.example.com:8080",
                "target_id": "target-proxy-set-1"
            }),
        ),
        (
            "/proxy/clear",
            json!({
                "enabled": false,
                "mode": "direct",
                "server": null,
                "target_id": "target-proxy-clear-1"
            }),
        ),
    ] {
        Mock::given(method("POST"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(mock_server)
            .await;
    }
}

async fn invoke_browser_operation(
    connector: &BrowserConnector,
    signing_key: &Ed25519SigningKey,
    operation: &str,
    input: serde_json::Value,
    approval_required: bool,
) -> serde_json::Value {
    let approval = approval_required.then(|| generate_execution_approval(operation, &input));
    let capability = generate_valid_token(signing_key, connector, operation);
    let mut request = json!({
        "operation": operation,
        "input": input,
        "capability_token": capability
    });
    if let Some(approval) = approval {
        request
            .as_object_mut()
            .expect("browser invoke request should be a JSON object")
            .insert(
                "approval_token".to_string(),
                serde_json::to_value(approval).expect("approval token should serialize"),
            );
    }

    connector
        .handle_invoke(request)
        .await
        .expect("browser operation should succeed")
}

fn push_browser_e2e_log(
    capture: &LogCapture,
    ctx: &AsyncTestContext,
    phase: &str,
    step_number: usize,
    assertions_passed: u64,
    details: &serde_json::Value,
) {
    capture
        .push_value(&json!({
            "timestamp": Utc::now().to_rfc3339(),
            "log_version": "v2",
            "test_name": "browser_control_connector_boundary_full_flow",
            "module": "fcp-browser",
            "phase": phase,
            "correlation_id": ctx.correlation_id(),
            "result": "pass",
            "duration_ms": 0,
            "assertions": { "passed": assertions_passed, "failed": 0 },
            "step_number": step_number,
            "run_id": ctx.run_id(),
            "scenario_id": ctx.scenario_id(),
            "details": details,
        }))
        .expect("structured e2e log entry should serialize");
}

fn request_header(request: &wiremock::Request, name: &str) -> String {
    request
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_string()
}

fn json_len(value: &serde_json::Value) -> u64 {
    serde_json::to_vec(value).map_or(0, |bytes| u64::try_from(bytes.len()).unwrap_or(u64::MAX))
}

// ============================================================================
// Happy-path operation tests
// ============================================================================

#[fcp_async_core::runtime::test]
async fn test_browser_control_connector_boundary_full_flow_e2e_logs() {
    let ctx = AsyncTestContext::for_scenario("browser-control-boundary-full-flow");
    let capture = LogCapture::new();
    let started = Instant::now();
    let mock_server = MockServer::start().await;
    mount_full_flow_browser_control(&mock_server).await;

    let mut connector = BrowserConnector::new();
    let operations = [
        "browser.navigate",
        "browser.screenshot",
        "browser.render_pdf",
        "browser.extract_text",
        "browser.extract_links",
        "browser.wait_for_selector",
        "browser.click",
        "browser.fill_form",
        "browser.evaluate_js",
        "browser.get_cookies",
        "browser.set_cookies",
        "browser.session.save",
        "browser.session.restore",
        "browser.session.describe",
        "browser.set_proxy",
        "browser.clear_proxy",
    ];
    let signing_key = setup_handshake(&mut connector, &operations).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let health = connector.handle_health().await.unwrap();
    assert_eq!(health["status"], "healthy");
    assert_eq!(
        health["browser_control_contract"]["control_plane"],
        "fcp-browser-control"
    );
    assert_eq!(
        health["browser_control_contract"]["control_modes"]["direct_cdp_websocket"]["proxy_support"],
        "proxy_unavailable_direct_cdp"
    );
    assert_eq!(
        health["browser_control_contract"]["control_modes"]["fcp_browser_control"]["proxy_support"],
        "available_when_proxy_operations_advertised"
    );
    push_browser_e2e_log(
        &capture,
        &ctx,
        "configure",
        0,
        3,
        &json!({
            "control_endpoint": mock_server.uri(),
            "capability_decision": "handshake_accepted",
            "contract_operation_count": health["browser_control_contract"]["operations"].as_array().map_or(0, Vec::len),
            "target_id": "connector-boundary",
            "cleanup_result": "pending",
        }),
    );

    let denied_capability = generate_valid_token(&signing_key, &connector, "browser.navigate");
    let denied = connector
        .handle_invoke(json!({
            "operation": "browser.evaluate_js",
            "input": { "expression": "document.cookie" },
            "capability_token": denied_capability
        }))
        .await;
    assert!(denied.is_err());
    assert_eq!(
        mock_server
            .received_requests()
            .await
            .unwrap_or_default()
            .len(),
        0
    );
    push_browser_e2e_log(
        &capture,
        &ctx,
        "capability_denial",
        1,
        2,
        &json!({
            "connector_operation": "browser.evaluate_js",
            "capability_decision": "denied_before_worker_route",
            "command_route": null,
            "target_id": null,
            "worker_request_sent": false,
            "timeout_checkpoint": "not_started",
            "cancellation_checkpoint": "not_started",
            "retry_decision": "not_started",
            "cleanup_result": "not_needed",
        }),
    );

    let mut results = Vec::new();
    for (operation, input, approval_required) in [
        (
            "browser.navigate",
            json!({ "url": "https://example.com/dashboard", "wait_until": "networkidle" }),
            false,
        ),
        (
            "browser.screenshot",
            json!({ "selector": "#dashboard", "full_page": false, "format": "png" }),
            false,
        ),
        (
            "browser.render_pdf",
            json!({ "format": "a4", "print_background": true, "max_pages": 4 }),
            false,
        ),
        (
            "browser.extract_text",
            json!({ "selector": "main", "output_mode": "markdown", "max_chars": 512 }),
            false,
        ),
        ("browser.extract_links", json!({ "selector": "nav" }), false),
        (
            "browser.wait_for_selector",
            json!({ "selector": ".ready", "state": "visible", "timeout_ms": 2500 }),
            false,
        ),
        (
            "browser.click",
            json!({ "selector": "button.next", "timeout_ms": 2000 }),
            false,
        ),
        (
            "browser.fill_form",
            json!({
                "fields": {
                    "#email": "agent@example.test",
                    "#remember": true
                },
                "submit_selector": "button[type=submit]"
            }),
            true,
        ),
        (
            "browser.evaluate_js",
            json!({ "expression": "({ ready: document.readyState === 'complete' })" }),
            true,
        ),
        (
            "browser.get_cookies",
            json!({ "domain": "example.com" }),
            true,
        ),
        (
            "browser.set_cookies",
            json!({
                "cookies": [
                    { "name": "session", "value": "abc123", "domain": "example.com", "path": "/" },
                    { "name": "pref", "value": "dark", "domain": "example.com", "path": "/" }
                ]
            }),
            true,
        ),
        (
            "browser.session.save",
            json!({
                "domain": "example.com",
                "lease_seq": 10,
                "lease_object_id": "browser-lease-save-10"
            }),
            true,
        ),
    ] {
        let result = invoke_browser_operation(
            &connector,
            &signing_key,
            operation,
            input,
            approval_required,
        )
        .await;
        results.push((operation, result));
    }

    let saved_state_object_id = results
        .iter()
        .find(|(operation, _)| *operation == "browser.session.save")
        .and_then(|(_, result)| result.get("state_object_id"))
        .and_then(serde_json::Value::as_str)
        .expect("session save should return a state object id")
        .to_string();

    for (operation, input, approval_required) in [
        (
            "browser.session.restore",
            json!({
                "state_object_id": saved_state_object_id,
                "lease_seq": 11,
                "lease_object_id": "browser-lease-restore-11"
            }),
            true,
        ),
        (
            "browser.session.describe",
            json!({ "state_object_id": saved_state_object_id }),
            false,
        ),
        (
            "browser.set_proxy",
            json!({
                "server": "http://proxy.example.com:8080",
                "bypass_list": ["localhost", "127.0.0.1"]
            }),
            true,
        ),
        ("browser.clear_proxy", json!({}), true),
    ] {
        let result = invoke_browser_operation(
            &connector,
            &signing_key,
            operation,
            input,
            approval_required,
        )
        .await;
        results.push((operation, result));
    }

    assert_eq!(results.len(), operations.len());
    assert_eq!(results[0].1["url"], "https://example.com/dashboard");
    assert_eq!(results[2].1["document_extraction"]["decision"], "deferred");
    assert!(
        results[7].1["audit"]["approval_token_id"]
            .as_str()
            .is_some()
    );
    assert_eq!(results[8].1["result"], "ready");
    assert_eq!(results[13].1["is_head"], true);
    assert_eq!(results[14].1["enabled"], true);
    assert_eq!(results[15].1["enabled"], false);

    let requests = mock_server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|request| request.url.path() != "/health")
        .collect::<Vec<_>>();
    let expected_routes = [
        BrowserE2eRouteExpectation {
            connector_operation: "browser.navigate",
            worker_operation: "browser.navigate",
            path: "/navigate",
            target_id: "target-nav-1",
            approval_required: false,
        },
        BrowserE2eRouteExpectation {
            connector_operation: "browser.screenshot",
            worker_operation: "browser.screenshot",
            path: "/screenshot",
            target_id: "target-capture-1",
            approval_required: false,
        },
        BrowserE2eRouteExpectation {
            connector_operation: "browser.render_pdf",
            worker_operation: "browser.render_pdf",
            path: "/pdf",
            target_id: "target-pdf-1",
            approval_required: false,
        },
        BrowserE2eRouteExpectation {
            connector_operation: "browser.extract_text",
            worker_operation: "browser.extract_text",
            path: "/extract_text",
            target_id: "target-text-1",
            approval_required: false,
        },
        BrowserE2eRouteExpectation {
            connector_operation: "browser.extract_links",
            worker_operation: "browser.extract_links",
            path: "/extract_links",
            target_id: "target-links-1",
            approval_required: false,
        },
        BrowserE2eRouteExpectation {
            connector_operation: "browser.wait_for_selector",
            worker_operation: "browser.wait_for_selector",
            path: "/wait_for_selector",
            target_id: "target-wait-1",
            approval_required: false,
        },
        BrowserE2eRouteExpectation {
            connector_operation: "browser.click",
            worker_operation: "browser.click",
            path: "/click",
            target_id: "target-click-1",
            approval_required: false,
        },
        BrowserE2eRouteExpectation {
            connector_operation: "browser.fill_form",
            worker_operation: "browser.fill_form",
            path: "/fill_form",
            target_id: "target-fill-1",
            approval_required: true,
        },
        BrowserE2eRouteExpectation {
            connector_operation: "browser.evaluate_js",
            worker_operation: "browser.evaluate_js",
            path: "/evaluate",
            target_id: "target-evaluate-1",
            approval_required: true,
        },
        BrowserE2eRouteExpectation {
            connector_operation: "browser.get_cookies",
            worker_operation: "browser.get_cookies",
            path: "/cookies",
            target_id: "target-cookies-1",
            approval_required: true,
        },
        BrowserE2eRouteExpectation {
            connector_operation: "browser.set_cookies",
            worker_operation: "browser.set_cookies",
            path: "/set_cookies",
            target_id: "target-set-cookies-1",
            approval_required: true,
        },
        BrowserE2eRouteExpectation {
            connector_operation: "browser.session.save",
            worker_operation: "browser.get_cookies",
            path: "/cookies",
            target_id: "target-cookies-1",
            approval_required: true,
        },
        BrowserE2eRouteExpectation {
            connector_operation: "browser.session.restore",
            worker_operation: "browser.set_cookies",
            path: "/set_cookies",
            target_id: "target-set-cookies-1",
            approval_required: true,
        },
        BrowserE2eRouteExpectation {
            connector_operation: "browser.set_proxy",
            worker_operation: "browser.set_proxy",
            path: "/proxy/set",
            target_id: "target-proxy-set-1",
            approval_required: true,
        },
        BrowserE2eRouteExpectation {
            connector_operation: "browser.clear_proxy",
            worker_operation: "browser.clear_proxy",
            path: "/proxy/clear",
            target_id: "target-proxy-clear-1",
            approval_required: true,
        },
    ];
    assert_eq!(requests.len(), expected_routes.len());

    for (index, (request, expected)) in requests.iter().zip(expected_routes).enumerate() {
        let request_body: serde_json::Value =
            serde_json::from_slice(&request.body).expect("worker request body should be JSON");
        let response_payload_bytes = results
            .iter()
            .find(|(operation, _)| *operation == expected.connector_operation)
            .map_or(0, |(_, result)| json_len(result));
        let timeout_ms = request_header(request, "X-FCP-Browser-Timeout-Ms");
        let response_budget = request_header(request, "X-FCP-Browser-Max-Response-Bytes");
        let target_scope = request_header(request, "X-FCP-Browser-Target-Scope");
        let target_selection = request_header(request, "X-FCP-Browser-Target-Selection");
        let stale_recovery = request_header(request, "X-FCP-Browser-Stale-Target-Recovery");
        let current_tab_guard = request_header(request, "X-FCP-Browser-Current-Tab-Guard");
        let export_guard = request_header(request, "X-FCP-Browser-Export-Guard");

        assert_eq!(request.url.path(), expected.path);
        assert_eq!(
            request_header(request, "X-FCP-Browser-Operation"),
            expected.worker_operation
        );
        assert!(!timeout_ms.is_empty());
        assert!(!response_budget.is_empty());
        assert!(!target_scope.is_empty());
        assert!(!target_selection.is_empty());

        push_browser_e2e_log(
            &capture,
            &ctx,
            "invoke",
            index + 2,
            8,
            &json!({
                "connector_operation": expected.connector_operation,
                "worker_operation": expected.worker_operation,
                "command_route": request.url.path(),
                "target_id": expected.target_id,
                "capability_decision": "granted",
                "approval_required": expected.approval_required,
                "approval_present": expected.approval_required,
                "timeout_checkpoint": {
                    "timeout_ms": timeout_ms,
                    "source": "worker_request_header"
                },
                "cancellation_checkpoint": {
                    "requested": false,
                    "source": "connector_boundary_e2e"
                },
                "payload_sizes": {
                    "request_bytes": u64::try_from(request.body.len()).unwrap_or(u64::MAX),
                    "response_bytes": response_payload_bytes
                },
                "retry_decision": "not_retried_status_200",
                "target_policy": {
                    "scope": target_scope,
                    "selection": target_selection,
                    "stale_target_recovery": stale_recovery,
                    "current_tab_guard": current_tab_guard,
                    "export_guard": export_guard
                },
                "request_body": request_body,
                "cleanup_result": "pending",
            }),
        );
    }

    let described = results
        .iter()
        .find(|(operation, _)| *operation == "browser.session.describe")
        .map(|(_, result)| result)
        .expect("session describe should have a result");
    push_browser_e2e_log(
        &capture,
        &ctx,
        "connector_state",
        expected_routes.len() + 2,
        3,
        &json!({
            "connector_operation": "browser.session.describe",
            "worker_operation": null,
            "command_route": "connector_state",
            "target_id": "session-store-head",
            "capability_decision": "granted",
            "timeout_checkpoint": "not_applicable_local_state",
            "cancellation_checkpoint": "not_applicable_local_state",
            "payload_sizes": {
                "request_bytes": 0,
                "response_bytes": json_len(described)
            },
            "retry_decision": "not_applicable_local_state",
            "cleanup_result": "pending",
        }),
    );

    let shutdown = connector.handle_shutdown(json!({})).await.unwrap();
    assert_eq!(shutdown["status"], "shutdown");
    push_browser_e2e_log(
        &capture,
        &ctx,
        "cleanup",
        expected_routes.len() + 3,
        2,
        &json!({
            "command_route": "connector_shutdown",
            "target_id": "connector-boundary",
            "capability_decision": "not_applicable_cleanup",
            "timeout_checkpoint": "not_applicable_cleanup",
            "cancellation_checkpoint": "not_requested",
            "payload_sizes": {
                "request_bytes": 2,
                "response_bytes": json_len(&shutdown)
            },
            "retry_decision": "not_applicable_cleanup",
            "cleanup_result": "shutdown_complete",
            "duration_ms": u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        }),
    );

    let log_jsonl = capture.jsonl();
    assert!(log_jsonl.contains("\"command_route\""));
    assert!(log_jsonl.contains("\"target_id\""));
    assert!(log_jsonl.contains("\"capability_decision\""));
    assert!(log_jsonl.contains("\"timeout_checkpoint\""));
    assert!(log_jsonl.contains("\"cancellation_checkpoint\""));
    assert!(log_jsonl.contains("\"payload_sizes\""));
    assert!(log_jsonl.contains("\"retry_decision\""));
    assert!(log_jsonl.contains("\"cleanup_result\""));
    capture.assert_valid();
}

#[fcp_async_core::runtime::test]
async fn test_browser_proxy_control_mode_e2e_jsonl() {
    let ctx = AsyncTestContext::for_scenario("browser-proxy-control-mode-e2e");
    let run_id = ctx.run_id().to_string();
    let proxy_input = json!({
        "server": "http://proxy.example.com:8080",
        "bypass_list": ["localhost"]
    });
    let proxy_hash = proxy_descriptor_hash(&proxy_input);

    let proxy_capable_contract = browser_control_contract_response().await;
    let proxy_capable_server = MockServer::start().await;
    mount_browser_control_health_body(&proxy_capable_server, proxy_capable_contract.clone()).await;
    Mock::given(method("POST"))
        .and(path("/proxy/set"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "enabled": true,
            "mode": "fixed_servers",
            "server": "http://proxy.example.com:8080"
        })))
        .mount(&proxy_capable_server)
        .await;

    let mut proxy_capable_connector = BrowserConnector::new();
    let proxy_capable_key =
        setup_handshake(&mut proxy_capable_connector, &["browser.set_proxy"]).await;
    setup_configure(&mut proxy_capable_connector, &proxy_capable_server.uri()).await;
    let proxy_capable_token = generate_valid_token(
        &proxy_capable_key,
        &proxy_capable_connector,
        "browser.set_proxy",
    );
    let proxy_capable_approval = generate_execution_approval("browser.set_proxy", &proxy_input);
    let proxy_capable_result = proxy_capable_connector
        .handle_invoke(json!({
            "operation": "browser.set_proxy",
            "input": proxy_input.clone(),
            "capability_token": proxy_capable_token,
            "approval_token": proxy_capable_approval
        }))
        .await
        .expect("proxy-capable worker should accept set_proxy");
    assert_eq!(proxy_capable_result["enabled"], true);
    let proxy_capable_requests = proxy_capable_server
        .received_requests()
        .await
        .unwrap_or_default();
    let proxy_capable_worker_request = proxy_capable_requests
        .iter()
        .find(|request| request.url.path() == "/proxy/set")
        .expect("proxy-capable worker should receive set_proxy");
    emit_proxy_control_evidence(
        &run_id,
        "proxy_capable_worker_acceptance",
        json!({
            "control_mode": "fcp_browser_control",
            "operation_id": "browser.set_proxy",
            "advertised_worker_operations": advertised_worker_operations(&proxy_capable_contract),
            "capability_decision": "granted",
            "approval_decision": "granted",
            "proxy_descriptor_hash": proxy_hash,
            "endpoint_kind": "worker_policy",
            "deny_reason": null,
            "timeout_checkpoint": {
                "health_preflight": "completed",
                "worker_timeout_ms": request_header(proxy_capable_worker_request, "X-FCP-Browser-Timeout-Ms")
            },
            "cancellation_checkpoint": "not_cancelled",
            "cleanup_result": "worker_request_completed",
            "skip_reason": null,
            "worker_request_sent": true
        }),
    );

    let non_proxy_contract = browser_control_contract_without_proxy_operations().await;
    let non_proxy_server = MockServer::start().await;
    mount_browser_control_health_body(&non_proxy_server, non_proxy_contract.clone()).await;
    let mut non_proxy_connector = BrowserConnector::new();
    let non_proxy_key = setup_handshake(&mut non_proxy_connector, &["browser.set_proxy"]).await;
    setup_configure(&mut non_proxy_connector, &non_proxy_server.uri()).await;
    let non_proxy_token =
        generate_valid_token(&non_proxy_key, &non_proxy_connector, "browser.set_proxy");
    let non_proxy_approval = generate_execution_approval("browser.set_proxy", &proxy_input);
    let non_proxy_error = non_proxy_connector
        .handle_invoke(json!({
            "operation": "browser.set_proxy",
            "input": proxy_input.clone(),
            "capability_token": non_proxy_token,
            "approval_token": non_proxy_approval
        }))
        .await
        .expect_err("worker without proxy operations should fail proxy dispatch");
    let non_proxy_error = format!("{non_proxy_error:?}");
    assert!(non_proxy_error.contains("proxy_unavailable_worker_contract"));
    assert!(
        non_proxy_server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .all(|request| request.url.path() != "/proxy/set")
    );
    emit_proxy_control_evidence(
        &run_id,
        "non_proxy_worker_preserved",
        json!({
            "control_mode": "fcp_browser_control",
            "operation_id": "browser.set_proxy",
            "advertised_worker_operations": advertised_worker_operations(&non_proxy_contract),
            "capability_decision": "granted",
            "approval_decision": "granted",
            "proxy_descriptor_hash": proxy_descriptor_hash(&proxy_input),
            "endpoint_kind": "worker_policy",
            "deny_reason": "proxy_unavailable_worker_contract",
            "timeout_checkpoint": {
                "health_preflight": "completed",
                "worker_timeout_ms": null
            },
            "cancellation_checkpoint": "not_started",
            "cleanup_result": "no_worker_request_sent",
            "skip_reason": null,
            "worker_request_sent": false
        }),
    );

    let invalid_policy_contract = browser_control_contract_with_invalid_proxy_policy().await;
    let invalid_policy_server = MockServer::start().await;
    mount_browser_control_health_body(&invalid_policy_server, invalid_policy_contract.clone())
        .await;
    let mut invalid_policy_connector = BrowserConnector::new();
    let invalid_policy_key =
        setup_handshake(&mut invalid_policy_connector, &["browser.set_proxy"]).await;
    setup_configure(&mut invalid_policy_connector, &invalid_policy_server.uri()).await;
    let invalid_policy_token = generate_valid_token(
        &invalid_policy_key,
        &invalid_policy_connector,
        "browser.set_proxy",
    );
    let invalid_policy_approval = generate_execution_approval("browser.set_proxy", &proxy_input);
    let invalid_policy_error = invalid_policy_connector
        .handle_invoke(json!({
            "operation": "browser.set_proxy",
            "input": proxy_input.clone(),
            "capability_token": invalid_policy_token,
            "approval_token": invalid_policy_approval
        }))
        .await
        .expect_err("invalid worker proxy policy should fail proxy dispatch");
    let invalid_policy_error = format!("{invalid_policy_error:?}");
    assert!(invalid_policy_error.contains("proxy_invalid_worker_contract"));
    emit_proxy_control_evidence(
        &run_id,
        "worker_policy_rejection",
        json!({
            "control_mode": "fcp_browser_control",
            "operation_id": "browser.set_proxy",
            "advertised_worker_operations": advertised_worker_operations(&invalid_policy_contract),
            "capability_decision": "granted",
            "approval_decision": "granted",
            "proxy_descriptor_hash": proxy_descriptor_hash(&proxy_input),
            "endpoint_kind": "worker_policy",
            "deny_reason": "proxy_invalid_worker_contract",
            "timeout_checkpoint": {
                "health_preflight": "completed",
                "worker_timeout_ms": null
            },
            "cancellation_checkpoint": "not_started",
            "cleanup_result": "no_worker_request_sent",
            "skip_reason": null,
            "worker_request_sent": false
        }),
    );

    let direct_client = BrowserClient::new(None)
        .expect("browser client should construct")
        .with_browser_url("ws://127.0.0.1:9222/devtools/page/proxy-proof-target");
    let direct_proxy = ProxyConfig {
        server: "http://proxy.example.com:8080".into(),
        bypass_list: Some(vec!["localhost".into()]),
        username: None,
        password: None,
    };
    let direct_set_error = direct_client
        .set_proxy(&direct_proxy)
        .await
        .expect_err("direct CDP set_proxy should fail closed");
    assert!(format!("{direct_set_error}").contains("proxy_unavailable_direct_cdp"));
    emit_proxy_control_evidence(
        &run_id,
        "direct_cdp_set_proxy_fail_closed",
        json!({
            "control_mode": "direct_cdp_websocket",
            "operation_id": "browser.set_proxy",
            "advertised_worker_operations": [],
            "capability_decision": "not_applicable_client_direct",
            "approval_decision": "not_applicable_client_direct",
            "proxy_descriptor_hash": proxy_descriptor_hash(&proxy_input),
            "endpoint_kind": "direct_cdp_websocket",
            "deny_reason": "proxy_unavailable_direct_cdp",
            "timeout_checkpoint": "not_started",
            "cancellation_checkpoint": "not_started",
            "cleanup_result": "no_network_request_started",
            "skip_reason": null,
            "worker_request_sent": false
        }),
    );

    let direct_clear_error = direct_client
        .clear_proxy()
        .await
        .expect_err("direct CDP clear_proxy should fail closed");
    assert!(format!("{direct_clear_error}").contains("proxy_unavailable_direct_cdp"));
    emit_proxy_control_evidence(
        &run_id,
        "direct_cdp_clear_proxy_fail_closed",
        json!({
            "control_mode": "direct_cdp_websocket",
            "operation_id": "browser.clear_proxy",
            "advertised_worker_operations": [],
            "capability_decision": "not_applicable_client_direct",
            "approval_decision": "not_applicable_client_direct",
            "proxy_descriptor_hash": proxy_descriptor_hash(&json!({})),
            "endpoint_kind": "direct_cdp_websocket",
            "deny_reason": "proxy_unavailable_direct_cdp",
            "timeout_checkpoint": "not_started",
            "cancellation_checkpoint": "not_started",
            "cleanup_result": "no_network_request_started",
            "skip_reason": null,
            "worker_request_sent": false
        }),
    );

    let approval_denial_server = MockServer::start().await;
    let mut approval_denial_connector = BrowserConnector::new();
    let approval_denial_key =
        setup_handshake(&mut approval_denial_connector, &["browser.set_proxy"]).await;
    setup_configure(
        &mut approval_denial_connector,
        &approval_denial_server.uri(),
    )
    .await;
    let approval_denial_token = generate_valid_token(
        &approval_denial_key,
        &approval_denial_connector,
        "browser.set_proxy",
    );
    let approval_denial_error = approval_denial_connector
        .handle_invoke(json!({
            "operation": "browser.set_proxy",
            "input": proxy_input.clone(),
            "capability_token": approval_denial_token
        }))
        .await
        .expect_err("proxy mutation should require approval before worker dispatch");
    assert!(format!("{approval_denial_error:?}").contains("ApprovalToken"));
    assert!(
        approval_denial_server
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty()
    );
    emit_proxy_control_evidence(
        &run_id,
        "approval_denial_before_dispatch",
        json!({
            "control_mode": "pre_dispatch",
            "operation_id": "browser.set_proxy",
            "advertised_worker_operations": [],
            "capability_decision": "granted",
            "approval_decision": "denied_before_worker_route",
            "proxy_descriptor_hash": proxy_descriptor_hash(&proxy_input),
            "endpoint_kind": "none",
            "deny_reason": "missing_approval_token",
            "timeout_checkpoint": "not_started",
            "cancellation_checkpoint": "not_started",
            "cleanup_result": "no_worker_request_sent",
            "skip_reason": null,
            "worker_request_sent": false
        }),
    );

    let capability_denial_server = MockServer::start().await;
    let mut capability_denial_connector = BrowserConnector::new();
    let capability_denial_key =
        setup_handshake(&mut capability_denial_connector, &["browser.navigate"]).await;
    setup_configure(
        &mut capability_denial_connector,
        &capability_denial_server.uri(),
    )
    .await;
    let wrong_capability_token = generate_valid_token(
        &capability_denial_key,
        &capability_denial_connector,
        "browser.navigate",
    );
    let capability_denial_approval = generate_execution_approval("browser.set_proxy", &proxy_input);
    let capability_denial_error = capability_denial_connector
        .handle_invoke(json!({
            "operation": "browser.set_proxy",
            "input": proxy_input.clone(),
            "capability_token": wrong_capability_token,
            "approval_token": capability_denial_approval
        }))
        .await
        .expect_err("wrong capability should fail before worker dispatch");
    assert!(format!("{capability_denial_error:?}").contains("OperationNotGranted"));
    assert!(
        capability_denial_server
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty()
    );
    emit_proxy_control_evidence(
        &run_id,
        "capability_denial_before_dispatch",
        json!({
            "control_mode": "pre_dispatch",
            "operation_id": "browser.set_proxy",
            "advertised_worker_operations": [],
            "capability_decision": "denied_before_worker_route",
            "approval_decision": "not_evaluated",
            "proxy_descriptor_hash": proxy_descriptor_hash(&proxy_input),
            "endpoint_kind": "none",
            "deny_reason": "operation_not_granted",
            "timeout_checkpoint": "not_started",
            "cancellation_checkpoint": "not_started",
            "cleanup_result": "no_worker_request_sent",
            "skip_reason": null,
            "worker_request_sent": false
        }),
    );
}

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
    assert_eq!(result["external_content"]["untrusted"], true);
    assert_eq!(result["external_content"]["kind"], "rendered_pdf");
    assert_eq!(result["document_extraction"]["decision"], "deferred");
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
    assert_eq!(result["output_mode"], "text");
    assert_eq!(result["external_content"]["untrusted"], true);
    assert_eq!(result["external_content"]["kind"], "page_text");
    assert_eq!(
        result["readability"]["decision"],
        "adopted_for_active_page_text"
    );
    assert_eq!(result["guardrails"]["truncated"], false);
    assert_eq!(result["guardrails"]["stripped_invisible_chars"], 0);
}

#[fcp_async_core::runtime::test]
async fn test_extract_text_applies_readable_content_guardrails() {
    let _ctx = AsyncTestContext::for_scenario("browser-extract-text-guardrails");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/extract_text"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "text": " First\u{200B} paragraph \n\n Second paragraph with more words ",
            "word_count": 8
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
            "input": {
                "output_mode": "markdown",
                "max_chars": 28
            },
            "capability_token": token
        }))
        .await
        .unwrap();

    assert_eq!(result["text"], "First paragraph\n\nSecond p");
    assert_eq!(result["output_mode"], "markdown");
    assert_eq!(result["guardrails"]["stripped_invisible_chars"], 1);
    assert_eq!(result["guardrails"]["truncated"], true);
    assert_eq!(result["guardrails"]["requested_max_chars"], 28);
}

#[fcp_async_core::runtime::test]
async fn test_render_pdf_rejects_page_count_over_requested_cap() {
    let _ctx = AsyncTestContext::for_scenario("browser-render-pdf-page-cap");
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/pdf"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "pdf_data": "JVBERi0xLjQK...",
            "page_count": 5
        })))
        .mount(&mock_server)
        .await;

    let mut connector = BrowserConnector::new();
    let key = setup_handshake(&mut connector, &["browser.render_pdf"]).await;
    setup_configure(&mut connector, &mock_server.uri()).await;

    let token = generate_valid_token(&key, &connector, "browser.render_pdf");
    let err = connector
        .handle_invoke(json!({
            "operation": "browser.render_pdf",
            "input": { "max_pages": 3 },
            "capability_token": token
        }))
        .await
        .unwrap_err();

    assert!(format!("{err}").contains("exceeds max_pages"));
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

    mount_browser_control_health(&mock_server).await;
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

    mount_browser_control_health(&mock_server).await;
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
