//! Local acceptance coverage for the LLM Router meta-connector.
//!
//! The router must return dispatch instructions only; it must not open provider
//! sockets itself. These tests keep a loopback listener as a tripwire while the
//! production connector paths run.

#![allow(
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]

use std::net::TcpListener;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use fcp_llm_router::connector::LlmRouterConnector;
use serde_json::{Value, json};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const BEAD_ID: &str = "flywheel_connectors-angoc.16.4";
const LOCAL_API_KEY: &str = "llm-router-local-secret-that-must-not-leak";

struct NoRequestLoopback {
    base_url: String,
    seen_connection: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl NoRequestLoopback {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback tripwire");
        listener
            .set_nonblocking(true)
            .expect("set listener nonblocking");
        let base_url = format!("http://{}", listener.local_addr().expect("local address"));
        let seen_connection = Arc::new(AtomicBool::new(false));
        let seen_for_thread = Arc::clone(&seen_connection);
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = Arc::clone(&stop);

        let handle = thread::spawn(move || {
            while !stop_for_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((_stream, _addr)) => {
                        seen_for_thread.store(true, Ordering::Relaxed);
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
        });

        Self {
            base_url,
            seen_connection,
            stop,
            handle: Some(handle),
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn saw_connection(&self) -> bool {
        self.seen_connection.load(Ordering::Relaxed)
    }

    fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            handle.join().expect("loopback tripwire thread joined");
        }
    }
}

impl Drop for NoRequestLoopback {
    fn drop(&mut self) {
        self.stop();
    }
}

fn route_only_config() -> Value {
    json!({
        "providers": [
            {
                "name": "deepseek",
                "api_key": LOCAL_API_KEY,
                "priority": 1,
                "models": [
                    {
                        "id": "deepseek-chat",
                        "capabilities": ["chat", "code"],
                        "context_window": 64000,
                        "cost_per_input_token": 0.000_000_14,
                        "cost_per_output_token": 0.000_000_28
                    }
                ]
            }
        ],
        "default_strategy": "cost",
        "budget": {
            "budget_usd": 1.0,
            "enforcement": "hard",
            "period": "session"
        }
    })
}

fn local_litellm_config(base_url: &str) -> Value {
    json!({
        "providers": [
            {
                "name": "litellm",
                "base_url": format!("{base_url}/v1"),
                "api_key": LOCAL_API_KEY,
                "priority": 1,
                "models": [
                    {
                        "id": "local-model",
                        "capabilities": ["chat"],
                        "context_window": 8192,
                        "cost_per_input_token": 0.0,
                        "cost_per_output_token": 0.0
                    }
                ]
            }
        ]
    })
}

fn print_artifact(case_name: &str, boundary: &Value) {
    let artifact = json!({
        "connector": "llm-router",
        "package": "fcp-llm-router",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "bead_id": BEAD_ID,
        "case": case_name,
        "command": "cargo test -p fcp-llm-router --test local_non_mock -- --nocapture",
        "git_revision": option_env!("GIT_REVISION").unwrap_or("worktree"),
        "fixture_mode": "loopback_tripwire",
        "provider_class": "router_only_dispatch",
        "request_response_boundary": boundary,
        "auth_gate": {
            "mode": "api_key_configured_for_downstream_provider",
            "router_contacts_provider": false,
            "secret_material_logged": false
        },
        "cleanup": "loopback_tripwire_thread_joined",
        "result": "passed"
    });
    println!("{artifact}");
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_route_returns_dispatch_without_provider_socket_use() {
    let mut tripwire = NoRequestLoopback::start();
    let mut connector = LlmRouterConnector::new();
    connector
        .handle_configure(route_only_config())
        .await
        .expect("configure fixed provider route-only router");

    let route = connector
        .handle_invoke(json!({
            "operation": "llm-router.route",
            "capability_token": "local-non-mock-capability",
            "input": {
                "messages": [
                    {
                        "role": "user",
                        "content": "Pick the cheapest provider for this local proof."
                    }
                ],
                "strategy": "cost",
                "max_tokens": 128
            }
        }))
        .await
        .expect("route should produce dispatch decision");
    let providers = connector
        .handle_invoke(json!({
            "operation": "llm-router.list_providers",
            "capability_token": "local-non-mock-admin-capability",
            "input": { "include_models": true }
        }))
        .await
        .expect("provider inventory should be available");
    let shutdown = connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown should return redacted totals");

    assert_eq!(route["dispatch_required"], true);
    assert_eq!(route["provider"], "deepseek");
    assert_eq!(route["model"], "deepseek-chat");
    assert_eq!(route["dispatch"]["operation"], "provider.chat_completion");
    assert_eq!(route["dispatch"]["auth_policy"], "api_key");
    assert!(route.get("response").is_none());
    assert_eq!(providers["providers"][0]["name"], "deepseek");
    assert_eq!(providers["providers"][0]["auth_policy"], "api_key");
    assert!(shutdown["total_cost_usd"].as_f64().unwrap_or_default() > 0.0);

    let serialized = serde_json::to_string(&json!({
        "route": route,
        "providers": providers,
        "shutdown": shutdown
    }))
    .expect("serialize local proof outputs");
    assert!(
        !serialized.contains(LOCAL_API_KEY),
        "local proof output must not leak provider API key"
    );
    assert!(
        !tripwire.saw_connection(),
        "router dispatch decision must not contact provider sockets"
    );

    print_artifact(
        "route_returns_dispatch_without_provider_socket_use",
        &json!({
            "selected_provider": "deepseek",
            "selected_model": "deepseek-chat",
            "dispatch_required": true,
            "provider_socket_requests": 0,
            "secret_material_logged": false
        }),
    );
    tripwire.stop();
}

#[fcp_async_core::runtime::test]
async fn local_non_mock_rejects_self_hosted_loopback_gateway_before_provider_traffic() {
    let mut tripwire = NoRequestLoopback::start();
    let mut connector = LlmRouterConnector::new();

    let error = connector
        .handle_configure(local_litellm_config(tripwire.base_url()))
        .await
        .expect_err("loopback LiteLLM endpoint should fail closed");
    let message = error.to_string();
    assert!(message.contains("operator-configured gateway base_url"));
    assert!(message.contains("self-hosted OpenAI-compatible runtimes"));
    assert!(
        !message.contains(LOCAL_API_KEY),
        "rejection error must not leak provider API key"
    );
    assert!(
        !tripwire.saw_connection(),
        "rejected loopback gateway must not receive provider traffic"
    );

    print_artifact(
        "rejects_self_hosted_loopback_gateway_before_provider_traffic",
        &json!({
            "rejected_provider": "litellm",
            "rejection": "self_hosted_loopback_gateway_requires_explicit_network_policy",
            "provider_socket_requests": 0,
            "secret_material_logged": false
        }),
    );
    tripwire.stop();
}
