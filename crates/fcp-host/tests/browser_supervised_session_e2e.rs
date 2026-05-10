//! Host-owned browser direct-CDP manager concurrency proof.
//!
//! This test lives in `fcp-host` because the host is the concurrency boundary
//! for simultaneous agent invokes. It uses the real `fcp-browser` connector
//! and its direct-CDP manager, but a local loopback TCP fixture instead of a
//! live browser or third-party page.

use std::net::TcpListener;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::Duration as StdDuration;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_browser::connector::BrowserConnector;
use fcp_core::{CapabilityConstraints, CapabilityToken};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use futures_util::future;
use serde_json::json;

fn git_revision() -> &'static str {
    option_env!("GIT_COMMIT")
        .or(option_env!("VERGEN_GIT_SHA"))
        .or(option_env!("SOURCE_DATE_EPOCH"))
        .unwrap_or("unknown")
}

fn capability_for_operation(operation: &'static str) -> &'static str {
    match operation {
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
        _ => operation,
    }
}

fn valid_token(
    signing_key: &Ed25519SigningKey,
    connector: &BrowserConnector,
    operation: &'static str,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("constraints should serialize");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability_for_operation(operation))
        .zone_id("z:work")
        .principal("agent:browser-host-e2e")
        .operations(&[operation])
        .issuer("node:browser-host-e2e")
        .target_instance(connector.instance_id())
        .validity(now, now + ChronoDuration::minutes(5))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("capability token should sign");
    CapabilityToken::from_raw(cose)
}

async fn handshake_browser_connector(connector: &mut BrowserConnector) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0_u8; 32],
            "capabilities_requested": ["browser.navigate", "browser.capture"]
        }))
        .await
        .expect("browser handshake should succeed");
    signing_key
}

fn start_hanging_cdp_handshake_fixture() -> (String, mpsc::Sender<()>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback CDP fixture");
    let addr = listener.local_addr().expect("fixture local address");
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let handle = thread::spawn(move || {
        let Ok((stream, _peer)) = listener.accept() else {
            return;
        };
        let _ = release_rx.recv_timeout(StdDuration::from_secs(5));
        drop(stream);
    });
    let url = format!("ws://{addr}/devtools/page/host-concurrency-target-secret");
    (url, release_tx, handle)
}

#[fcp_async_core::runtime::test]
async fn two_concurrent_direct_cdp_invokes_same_browser_instance_one_defers_at_manager() {
    let (browser_url, release_fixture, fixture_thread) = start_hanging_cdp_handshake_fixture();
    let mut connector = BrowserConnector::new();
    let signing_key = handshake_browser_connector(&mut connector).await;
    connector
        .handle_configure(json!({ "browser_url": browser_url }))
        .await
        .expect("direct-CDP browser configure should succeed");

    let navigate_token = valid_token(&signing_key, &connector, "browser.navigate");
    let screenshot_token = valid_token(&signing_key, &connector, "browser.screenshot");
    let connector = Arc::new(connector);
    let first_connector = Arc::clone(&connector);
    let second_connector = Arc::clone(&connector);

    let first = async move {
        first_connector
            .handle_invoke(json!({
                "operation": "browser.navigate",
                "input": {
                    "url": "https://example.test/private-dashboard",
                    "wait_until": "load",
                    "timeout_ms": 750
                },
                "capability_token": navigate_token
            }))
            .await
    };
    let second = async move {
        fcp_async_core::time::sleep(StdDuration::from_millis(50)).await;
        second_connector
            .handle_invoke(json!({
                "operation": "browser.screenshot",
                "input": { "format": "png", "full_page": false },
                "capability_token": screenshot_token
            }))
            .await
    };

    let (first_result, second_result) = future::join(first, second).await;
    let _ = release_fixture.send(());
    fixture_thread
        .join()
        .expect("fixture thread should exit after release");

    let first_error = first_result.expect_err("hanging CDP handshake should fail first invoke");
    let first_error_text = first_error.to_string();
    assert!(
        first_error_text.contains("WebSocket")
            || first_error_text.contains("exceeded")
            || first_error_text.contains("direct navigate failed"),
        "unexpected first invoke error: {first_error_text}"
    );

    let second_error = second_result.expect_err("second invoke should defer at manager");
    let second_error_text = second_error.to_string();
    assert!(
        second_error_text.contains("already owns operation browser.navigate"),
        "unexpected second invoke error: {second_error_text}"
    );

    let manager_jsonl = connector
        .direct_cdp_manager_events_jsonl_for_test()
        .expect("manager events should be available");
    assert!(manager_jsonl.contains("\"operation_id\":\"browser.navigate\""));
    assert!(
        manager_jsonl.contains("\"cleanup_result\":\"connect_failed_cleanup\"")
            || manager_jsonl.contains("\"cleanup_result\":\"lease_dropped_cleanup\"")
    );
    assert!(!manager_jsonl.contains("host-concurrency-target-secret"));
    assert!(!manager_jsonl.contains("private-dashboard"));
    assert!(!manager_jsonl.contains("browser.screenshot"));

    let event_count = manager_jsonl.lines().count();
    println!(
        "BROWSER_SUPERVISED_SESSION_HOST_E2E {}",
        json!({
            "schema_version": "fcp-browser-host-supervised-session-e2e.v1",
            "command_line": "cargo test -p fcp-host --test browser_supervised_session_e2e",
            "git_revision": git_revision(),
            "run_id": "browser-host-supervised-concurrent-direct-cdp",
            "connector": "fcp-browser",
            "endpoint_kind": "direct_cdp_websocket",
            "first_invoke": {
                "operation_id": "browser.navigate",
                "status": "failed_after_manager_lease",
                "error_class": "cdp_fixture_handshake_timeout_or_connect_failure"
            },
            "second_invoke": {
                "operation_id": "browser.screenshot",
                "status": "deferred_before_cdp_connect",
                "defer_reason": "manager_active_lease"
            },
            "manager_event_count": event_count,
            "redaction": {
                "raw_target_id": false,
                "raw_url": false,
                "raw_page_url": false
            },
            "cleanup_result": "fixture_released_no_orphan_thread",
            "skip_reason": null
        })
    );
}
