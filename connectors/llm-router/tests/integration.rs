//! Integration tests for the LLM Router connector.
//!
//! Tests the connector via `handle_invoke` and `handle_configure` following
//! the FCP2 connector test patterns.

#![allow(clippy::unreadable_literal)]

use fcp_llm_router::connector::LlmRouterConnector;
use serde_json::{Value, json};

fn test_config() -> serde_json::Value {
    json!({
        "providers": [
            {
                "name": "anthropic",
                "base_url": "https://api.anthropic.com",
                "api_key": "test-key-anthropic",
                "priority": 1,
                "models": [
                    {
                        "id": "claude-sonnet-4",
                        "capabilities": ["code", "tool_use"],
                        "context_window": 200000,
                        "cost_per_input_token": 0.000003,
                        "cost_per_output_token": 0.000015
                    },
                    {
                        "id": "claude-haiku-4",
                        "capabilities": ["code"],
                        "context_window": 200000,
                        "cost_per_input_token": 0.0000008,
                        "cost_per_output_token": 0.000004
                    }
                ]
            },
            {
                "name": "openai",
                "base_url": "https://api.openai.com",
                "api_key": "test-key-openai",
                "priority": 2,
                "models": [
                    {
                        "id": "gpt-4o",
                        "capabilities": ["code", "vision", "tool_use"],
                        "context_window": 128000,
                        "cost_per_input_token": 0.000005,
                        "cost_per_output_token": 0.000015
                    }
                ]
            },
            {
                "name": "google-ai",
                "base_url": "https://generativelanguage.googleapis.com",
                "api_key": "test-key-google",
                "priority": 3,
                "models": [
                    {
                        "id": "gemini-2.0-flash",
                        "capabilities": ["code", "long_context"],
                        "context_window": 1000000,
                        "cost_per_input_token": 0.0000001,
                        "cost_per_output_token": 0.0000004
                    }
                ]
            }
        ],
        "default_strategy": "cost",
        "budget": {
            "budget_usd": 50.0,
            "enforcement": "hard",
            "period": "session"
        }
    })
}

async fn configured_connector() -> LlmRouterConnector {
    let mut c = LlmRouterConnector::new();
    c.handle_configure(test_config()).await.unwrap();
    c
}

fn operation_by_id<'a>(introspection: &'a Value, id: &str) -> Option<&'a Value> {
    introspection
        .get("operations")
        .and_then(Value::as_array)
        .and_then(|operations| {
            operations
                .iter()
                .find(|op| op.get("id").and_then(Value::as_str) == Some(id))
        })
}

#[fcp_async_core::runtime::test]
async fn configure_with_three_providers() {
    let mut connector = LlmRouterConnector::new();
    let result = connector.handle_configure(test_config()).await.unwrap();

    assert_eq!(result["status"], "configured");
    let providers = result["providers"].as_array().unwrap();
    assert_eq!(providers.len(), 3);
    assert!(providers.contains(&json!("anthropic")));
    assert!(providers.contains(&json!("openai")));
    assert!(providers.contains(&json!("google-ai")));

    // Check provisioning readiness
    let provisioning = result["provisioning"].as_array().unwrap();
    assert_eq!(provisioning.len(), 3);
    for p in provisioning {
        assert_eq!(p["auth_ok"], true);
        assert_eq!(p["auth_mode"], "api_key");
        assert_eq!(p["network_ok"], true);
        assert_eq!(p["models_ok"], true);
    }
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_empty_providers() {
    let mut connector = LlmRouterConnector::new();
    let result = connector.handle_configure(json!({"providers": []})).await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_missing_providers() {
    let mut connector = LlmRouterConnector::new();
    let result = connector.handle_configure(json!({})).await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn introspect_lists_five_operations() {
    let connector = LlmRouterConnector::new();
    let result = connector.handle_introspect().await.unwrap();
    let ops = result["operations"].as_array().unwrap();
    assert_eq!(ops.len(), 5);
}

#[fcp_async_core::runtime::test]
async fn route_output_schema_matches_decision_result_contract() {
    let mut connector = configured_connector().await;
    let introspection = connector.handle_introspect().await.unwrap();
    let route_operation =
        operation_by_id(&introspection, "llm-router.route").expect("missing route operation");
    let summary = route_operation["summary"].as_str().unwrap();
    assert!(
        summary.contains("routing decision"),
        "route summary must not imply inference output: {summary}"
    );

    let schema = &route_operation["output_schema"];
    let required = schema["required"].as_array().unwrap();
    let required_fields: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();
    let properties = &schema["properties"];

    assert!(!required_fields.contains(&"response"));
    assert!(properties.get("response").is_none());

    let result = connector
        .handle_invoke(json!({
            "operation": "llm-router.route",
            "capability_token": "test",
            "input": {
                "messages": [{"role": "user", "content": "Hello, how are you?"}]
            }
        }))
        .await
        .unwrap();

    for field in [
        "dispatch_required",
        "dispatch_instruction",
        "provider",
        "model",
        "usage",
        "cost_usd",
        "routing_decision",
        "provenance",
    ] {
        assert!(
            required_fields.contains(&field),
            "route schema should require {field}"
        );
        assert!(
            result.get(field).is_some(),
            "route result missing required schema field {field}"
        );
    }

    assert_eq!(result["dispatch_required"].as_bool(), Some(true));
    assert!(
        result["dispatch_instruction"]
            .as_str()
            .unwrap()
            .contains(".chat_completion")
    );
    assert!(result.get("response").is_none());
}

#[fcp_async_core::runtime::test]
async fn route_with_cost_strategy() {
    let mut connector = configured_connector().await;

    let result = connector
        .handle_invoke(json!({
            "operation": "llm-router.route",
            "capability_token": "test",
            "input": {
                "messages": [{"role": "user", "content": "Hello, how are you?"}],
                "strategy": "cost"
            }
        }))
        .await
        .unwrap();

    // Cost strategy should select the cheapest provider (google-ai/gemini-2.0-flash)
    assert_eq!(result["provider"], "google-ai");
    assert_eq!(result["model"], "gemini-2.0-flash");
    assert!(result["cost_usd"].as_f64().unwrap() > 0.0);

    let decision = &result["routing_decision"];
    assert_eq!(decision["strategy_used"], "cost");
    assert!(decision["reason"].as_str().unwrap().contains("lowest cost"));
}

#[fcp_async_core::runtime::test]
async fn route_with_capability_requirement() {
    let mut connector = configured_connector().await;

    let result = connector
        .handle_invoke(json!({
            "operation": "llm-router.route",
            "capability_token": "test",
            "input": {
                "messages": [{"role": "user", "content": "Describe this image"}],
                "strategy": "cost",
                "required_capabilities": ["vision"]
            }
        }))
        .await
        .unwrap();

    // Only OpenAI has vision capability
    assert_eq!(result["provider"], "openai");
    assert_eq!(result["model"], "gpt-4o");
}

#[fcp_async_core::runtime::test]
async fn route_with_fallback_strategy() {
    let mut connector = configured_connector().await;

    let result = connector
        .handle_invoke(json!({
            "operation": "llm-router.route",
            "capability_token": "test",
            "input": {
                "messages": [{"role": "user", "content": "Hello"}],
                "strategy": "fallback"
            }
        }))
        .await
        .unwrap();

    // Fallback uses priority order, anthropic is priority 1
    assert_eq!(result["provider"], "anthropic");
}

#[fcp_async_core::runtime::test]
async fn route_provenance_metadata() {
    let mut connector = configured_connector().await;

    let result = connector
        .handle_invoke(json!({
            "operation": "llm-router.route",
            "capability_token": "test",
            "input": {
                "messages": [{"role": "user", "content": "Test"}]
            }
        }))
        .await
        .unwrap();

    let provenance = &result["provenance"];
    assert!(provenance.get("source").is_some());
    assert!(provenance.get("model").is_some());
    assert_eq!(provenance["integrity"], "untrusted");
    assert_eq!(provenance["chunk_count"], 1);
    let taint = provenance["taint"].as_array().unwrap();
    assert!(taint.contains(&json!("AI_GENERATED")));
}

#[fcp_async_core::runtime::test]
async fn route_empty_messages_fails() {
    let mut connector = configured_connector().await;

    let result = connector
        .handle_invoke(json!({
            "operation": "llm-router.route",
            "capability_token": "test",
            "input": {
                "messages": []
            }
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn estimate_cost_all_providers() {
    let mut connector = configured_connector().await;

    let result = connector
        .handle_invoke(json!({
            "operation": "llm-router.estimate_cost",
            "capability_token": "test",
            "input": {
                "messages": [{"role": "user", "content": "Write me a poem about Rust programming"}]
            }
        }))
        .await
        .unwrap();

    let estimates = result["estimates"].as_array().unwrap();
    // 2 anthropic models + 1 openai + 1 google-ai = 4 estimates
    assert_eq!(estimates.len(), 4);

    // Should be sorted by cost ascending
    for window in estimates.windows(2) {
        let cost_a = window[0]["estimated_cost_usd"].as_f64().unwrap();
        let cost_b = window[1]["estimated_cost_usd"].as_f64().unwrap();
        assert!(cost_a <= cost_b);
    }

    // Recommended should be the cheapest available
    let recommended = &result["recommended"];
    assert!(recommended.get("provider").is_some());
}

#[fcp_async_core::runtime::test]
async fn estimate_cost_filtered_providers() {
    let mut connector = configured_connector().await;

    let result = connector
        .handle_invoke(json!({
            "operation": "llm-router.estimate_cost",
            "capability_token": "test",
            "input": {
                "messages": [{"role": "user", "content": "Hello"}],
                "providers": ["anthropic"]
            }
        }))
        .await
        .unwrap();

    let estimates = result["estimates"].as_array().unwrap();
    // Only anthropic models (2)
    assert_eq!(estimates.len(), 2);
    for est in estimates {
        assert_eq!(est["provider"], "anthropic");
    }
}

#[fcp_async_core::runtime::test]
async fn list_providers_without_models() {
    let mut connector = configured_connector().await;

    let result = connector
        .handle_invoke(json!({
            "operation": "llm-router.list_providers",
            "capability_token": "test",
            "input": {}
        }))
        .await
        .unwrap();

    let providers = result["providers"].as_array().unwrap();
    assert_eq!(providers.len(), 3);

    for p in providers {
        assert!(p.get("name").is_some());
        assert!(p.get("status").is_some());
        assert!(p.get("capabilities").is_some());
        // Models should not be included by default
        assert!(p.get("models").is_none());
    }
}

#[fcp_async_core::runtime::test]
async fn list_providers_with_models() {
    let mut connector = configured_connector().await;

    let result = connector
        .handle_invoke(json!({
            "operation": "llm-router.list_providers",
            "capability_token": "test",
            "input": {"include_models": true}
        }))
        .await
        .unwrap();

    let providers = result["providers"].as_array().unwrap();
    for p in providers {
        assert!(p.get("models").is_some());
    }
}

#[fcp_async_core::runtime::test]
async fn usage_tracking_across_routes() {
    let mut connector = configured_connector().await;

    // Route two requests
    for _ in 0..2 {
        connector
            .handle_invoke(json!({
                "operation": "llm-router.route",
                "capability_token": "test",
                "input": {
                    "messages": [{"role": "user", "content": "Hello"}]
                }
            }))
            .await
            .unwrap();
    }

    let usage = connector
        .handle_invoke(json!({
            "operation": "llm-router.get_usage",
            "capability_token": "test",
            "input": {"group_by": "provider"}
        }))
        .await
        .unwrap();

    assert_eq!(usage["requests_total"], 2);
    assert!(usage["total_cost_usd"].as_f64().unwrap() > 0.0);
    assert!(usage.get("breakdown").is_some());
}

#[fcp_async_core::runtime::test]
async fn budget_tracks_spending() {
    let mut connector = configured_connector().await;

    // Route a request
    connector
        .handle_invoke(json!({
            "operation": "llm-router.route",
            "capability_token": "test",
            "input": {
                "messages": [{"role": "user", "content": "Hello"}]
            }
        }))
        .await
        .unwrap();

    let budget = connector
        .handle_invoke(json!({
            "operation": "llm-router.get_budget",
            "capability_token": "test",
            "input": {}
        }))
        .await
        .unwrap();

    assert_eq!(budget["budget_usd"], 50.0);
    assert!(budget["spent_usd"].as_f64().unwrap() > 0.0);
    assert!(budget["remaining_usd"].as_f64().unwrap() < 50.0);
}

#[fcp_async_core::runtime::test]
async fn unknown_operation_fails() {
    let mut connector = configured_connector().await;

    let result = connector
        .handle_invoke(json!({
            "operation": "llm-router.unknown",
            "capability_token": "test",
            "input": {}
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn missing_capability_token_fails() {
    let mut connector = configured_connector().await;

    let result = connector
        .handle_invoke(json!({
            "operation": "llm-router.route",
            "input": {
                "messages": [{"role": "user", "content": "Hello"}]
            }
        }))
        .await;

    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn doctor_check_structure() {
    let connector = configured_connector().await;

    let result = connector.handle_doctor().await.unwrap();

    assert_eq!(result["status"], "healthy");
    let checks = result["checks"].as_array().unwrap();
    assert!(!checks.is_empty());

    // Check that all expected checks exist
    let check_names: Vec<&str> = checks
        .iter()
        .filter_map(|c| c.get("name").and_then(|v| v.as_str()))
        .collect();
    assert!(check_names.contains(&"configuration"));
    assert!(check_names.contains(&"providers"));
    assert!(check_names.contains(&"network_constraints"));
    assert!(check_names.contains(&"credential_injection"));
    assert!(check_names.contains(&"budget"));
}

#[fcp_async_core::runtime::test]
async fn self_check_structure() {
    let connector = configured_connector().await;

    let result = connector.handle_self_check().await.unwrap();

    assert_eq!(result["ready"], true);
    assert_eq!(result["status"], "ok");
    assert!(result.get("reasons").is_some());
    assert!(result.get("details").is_some());
    assert_eq!(result["details"]["provider_count"], 3);
}

#[fcp_async_core::runtime::test]
async fn shutdown_reports_cost() {
    let mut connector = configured_connector().await;

    // Route a request first
    connector
        .handle_invoke(json!({
            "operation": "llm-router.route",
            "capability_token": "test",
            "input": {
                "messages": [{"role": "user", "content": "Hello"}]
            }
        }))
        .await
        .unwrap();

    let result = connector.handle_shutdown(json!({})).await.unwrap();

    assert_eq!(result["status"], "shutdown");
    assert!(result["total_cost_usd"].as_f64().unwrap() > 0.0);
}

// ─── Provisioning-specific tests ─────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn configure_rejects_missing_credentials() {
    let mut connector = LlmRouterConnector::new();
    let result = connector
        .handle_configure(json!({
            "providers": [{
                "name": "anthropic",
                "base_url": "https://api.anthropic.com",
                "models": []
            }]
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_dual_credentials() {
    let mut connector = LlmRouterConnector::new();
    let result = connector
        .handle_configure(json!({
            "providers": [{
                "name": "anthropic",
                "base_url": "https://api.anthropic.com",
                "api_key": "key-123",
                "credential_id": "cred-123",
                "models": []
            }]
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_empty_api_key() {
    let mut connector = LlmRouterConnector::new();
    let result = connector
        .handle_configure(json!({
            "providers": [{
                "name": "anthropic",
                "base_url": "https://api.anthropic.com",
                "api_key": "  ",
                "models": []
            }]
        }))
        .await;
    // Empty/whitespace key should be rejected (trimmed to empty)
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_header_unsafe_api_key_without_leaking_it() {
    let mut connector = LlmRouterConnector::new();
    let result = connector
        .handle_configure(json!({
            "providers": [{
                "name": "anthropic",
                "base_url": "https://api.anthropic.com",
                "api_key": "sk-valid\r\nx-injected: bad",
                "models": []
            }]
        }))
        .await;
    let err = result.unwrap_err().to_string();
    assert!(err.contains("valid HTTP Authorization header value"));
    assert!(!err.contains("sk-valid"));
    assert!(!err.contains("x-injected"));
}

#[fcp_async_core::runtime::test]
async fn configure_with_credential_id_reports_secretless() {
    let mut connector = LlmRouterConnector::new();
    let result = connector
        .handle_configure(json!({
            "providers": [{
                "name": "anthropic",
                "base_url": "https://api.anthropic.com",
                "credential_id": "550e8400-e29b-41d4-a716-446655440000",
                "models": [{
                    "id": "claude-sonnet-4",
                    "capabilities": ["code"],
                    "context_window": 200000,
                    "cost_per_input_token": 0.000003,
                    "cost_per_output_token": 0.000015
                }]
            }]
        }))
        .await
        .unwrap();

    let provisioning = result["provisioning"].as_array().unwrap();
    assert_eq!(provisioning[0]["auth_mode"], "credential_id");
    assert_eq!(provisioning[0]["auth_ok"], true);

    // Self check should note credential injection
    let check = connector.handle_self_check().await.unwrap();
    assert_eq!(check["ready"], true);
    let reasons = check["reasons"].as_array().unwrap();
    assert!(
        reasons
            .iter()
            .any(|r| r["code"] == "credential_injection_required")
    );
}

#[fcp_async_core::runtime::test]
async fn configure_cloudflare_ai_gateway_builds_descriptor_url_and_preserves_passthrough_models() {
    let mut connector = LlmRouterConnector::new();
    let provider_key = "provider-openai-secret";
    let gateway_key = "cloudflare-gateway-secret";
    let result = connector
        .handle_configure(json!({
            "providers": [{
                "name": "cloudflare-ai-gateway",
                "account_id": "account_123",
                "gateway_id": "gateway-prod",
                "api_key": provider_key,
                "cloudflare_gateway_api_key": gateway_key,
                "models": [{
                    "id": "openrouter/openai/gpt-4o",
                    "capabilities": ["vision", "tool_use"],
                    "context_window": 128000,
                    "cost_per_input_token": 0.000005,
                    "cost_per_output_token": 0.000015
                }]
            }]
        }))
        .await
        .unwrap();

    let provisioning = result["provisioning"].as_array().unwrap();
    assert_eq!(provisioning[0]["name"], "cloudflare-ai-gateway");
    assert_eq!(provisioning[0]["network_ok"], true);
    assert_eq!(provisioning[0]["models_ok"], true);

    let providers = connector
        .handle_invoke(json!({
            "operation": "llm-router.list_providers",
            "capability_token": "test",
            "input": {"include_models": true}
        }))
        .await
        .unwrap();
    let provider = &providers["providers"].as_array().unwrap()[0];
    assert_eq!(provider["name"], "cloudflare-ai-gateway");
    assert_eq!(provider["passthrough_provider_models"], true);
    assert_eq!(provider["models"][0]["id"], "openrouter/openai/gpt-4o");
    assert_eq!(provider["models"][0]["cost_per_input_token"], 0.000005);

    let doctor = connector.handle_doctor().await.unwrap();
    let self_check = connector.handle_self_check().await.unwrap();
    let output = format!(
        "{}{}{}",
        serde_json::to_string(&result).unwrap(),
        serde_json::to_string(&doctor).unwrap(),
        serde_json::to_string(&self_check).unwrap()
    );
    assert!(!output.contains(provider_key));
    assert!(!output.contains(gateway_key));
    assert!(output.contains("api_key:[redacted]") || output.contains("\"auth_mode\":\"api_key\""));
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_cloudflare_base_url_override() {
    let mut connector = LlmRouterConnector::new();
    let result = connector
        .handle_configure(json!({
            "providers": [{
                "name": "cloudflare-ai-gateway",
                "base_url": "https://gateway.ai.cloudflare.com/v1/other/path/openai",
                "account_id": "account_123",
                "gateway_id": "gateway-prod",
                "api_key": "provider-key",
                "models": []
            }]
        }))
        .await;
    let err = result.unwrap_err().to_string();
    assert!(err.contains("base_url is built from account_id and gateway_id"));
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_cloudflare_path_query_fragment_inputs() {
    for (field, account_id, gateway_id) in [
        ("account_id", "account/123", "gateway-prod"),
        ("account_id", "account?123", "gateway-prod"),
        ("gateway_id", "account_123", "gateway#prod"),
    ] {
        let mut connector = LlmRouterConnector::new();
        let result = connector
            .handle_configure(json!({
                "providers": [{
                    "name": "cloudflare-ai-gateway",
                    "account_id": account_id,
                    "gateway_id": gateway_id,
                    "api_key": "provider-key",
                    "models": []
                }]
            }))
            .await;
        let err = result.unwrap_err().to_string();
        assert!(err.contains(field), "error should name {field}: {err}");
    }
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_cloudflare_gateway_header_injection_without_leaking_secret() {
    let mut connector = LlmRouterConnector::new();
    let gateway_key = "cf-good\r\nx-injected: bad";
    let result = connector
        .handle_configure(json!({
            "providers": [{
                "name": "cloudflare-ai-gateway",
                "account_id": "account_123",
                "gateway_id": "gateway-prod",
                "api_key": "provider-key",
                "cloudflare_gateway_api_key": gateway_key,
                "models": []
            }]
        }))
        .await;
    let err = result.unwrap_err().to_string();
    assert!(err.contains("cloudflare_gateway_api_key must be a valid HTTP header value"));
    assert!(!err.contains("cf-good"));
    assert!(!err.contains("x-injected"));
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_gateway_host_reserved_for_wrong_provider_descriptor() {
    let mut connector = LlmRouterConnector::new();
    let result = connector
        .handle_configure(json!({
            "providers": [{
                "name": "evil",
                "base_url": "https://gateway.ai.cloudflare.com",
                "api_key": "provider-key",
                "models": [{
                    "id": "evil-model",
                    "capabilities": [],
                    "context_window": 4096,
                    "cost_per_input_token": 0.0001,
                    "cost_per_output_token": 0.0001
                }]
            }]
        }))
        .await;
    let err = result.unwrap_err().to_string();
    assert!(err.contains("reserved for descriptor(s) 'cloudflare-ai-gateway'"));
}

#[fcp_async_core::runtime::test]
async fn configure_vercel_ai_gateway_uses_fixed_descriptor_and_aliases() {
    let mut connector = LlmRouterConnector::new();
    let secret_key = "vercel-gateway-secret";
    let result = connector
        .handle_configure(json!({
            "providers": [{
                "name": "vercel-ai-gateway",
                "api_key": secret_key,
                "models": [
                    {
                        "id": "sonnet-4.6",
                        "capabilities": ["code", "tool_use"],
                        "context_window": 200000,
                        "cost_per_input_token": 0.000003,
                        "cost_per_output_token": 0.000015
                    },
                    {
                        "id": "openai/gpt-4o",
                        "capabilities": ["vision"],
                        "context_window": 128000,
                        "cost_per_input_token": 0.000005,
                        "cost_per_output_token": 0.000015
                    }
                ]
            }]
        }))
        .await
        .unwrap();

    let provisioning = result["provisioning"].as_array().unwrap();
    assert_eq!(provisioning[0]["name"], "vercel-ai-gateway");
    assert_eq!(provisioning[0]["network_ok"], true);
    assert_eq!(provisioning[0]["auth_mode"], "api_key");

    let providers = connector
        .handle_invoke(json!({
            "operation": "llm-router.list_providers",
            "capability_token": "test",
            "input": {"include_models": true}
        }))
        .await
        .unwrap();
    let provider = &providers["providers"].as_array().unwrap()[0];
    assert_eq!(provider["name"], "vercel-ai-gateway");
    assert_eq!(provider["passthrough_provider_models"], true);
    assert_eq!(provider["models"][0]["id"], "anthropic/claude-sonnet-4-6");
    assert_eq!(provider["models"][1]["id"], "openai/gpt-4o");
    assert_eq!(provider["models"][0]["cost_per_output_token"], 0.000015);

    let result_str = serde_json::to_string(&result).unwrap();
    assert!(!result_str.contains(secret_key));
}

#[fcp_async_core::runtime::test]
async fn configure_vercel_ai_gateway_accepts_credential_id_secretless() {
    let mut connector = LlmRouterConnector::new();
    let result = connector
        .handle_configure(json!({
            "providers": [{
                "name": "vercel-ai-gateway",
                "credential_id": "vercel-oidc-or-secret-ref",
                "models": [{
                    "id": "opus-4.6",
                    "capabilities": ["code"],
                    "context_window": 200000,
                    "cost_per_input_token": 0.000003,
                    "cost_per_output_token": 0.000015
                }]
            }]
        }))
        .await
        .unwrap();

    let provisioning = result["provisioning"].as_array().unwrap();
    assert_eq!(provisioning[0]["auth_mode"], "credential_id");
    assert_eq!(provisioning[0]["network_ok"], true);
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_vercel_base_url_override() {
    let mut connector = LlmRouterConnector::new();
    let result = connector
        .handle_configure(json!({
            "providers": [{
                "name": "vercel-ai-gateway",
                "base_url": "https://evil.example.com/v1",
                "api_key": "provider-key",
                "models": []
            }]
        }))
        .await;
    let err = result.unwrap_err().to_string();
    assert!(err.contains("fixed gateway-provider descriptors do not accept base_url overrides"));
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_vercel_gateway_host_reserved_for_wrong_provider_descriptor() {
    let mut connector = LlmRouterConnector::new();
    let result = connector
        .handle_configure(json!({
            "providers": [{
                "name": "evil",
                "base_url": "https://ai-gateway.vercel.sh/v1",
                "api_key": "provider-key",
                "models": [{
                    "id": "evil-model",
                    "capabilities": [],
                    "context_window": 4096,
                    "cost_per_input_token": 0.0001,
                    "cost_per_output_token": 0.0001
                }]
            }]
        }))
        .await;
    let err = result.unwrap_err().to_string();
    assert!(err.contains("reserved for descriptor(s) 'vercel-ai-gateway'"));
}

#[fcp_async_core::runtime::test]
async fn configure_litellm_gateway_uses_operator_base_url_and_image_contract() {
    let mut connector = LlmRouterConnector::new();
    let secret_key = "litellm-gateway-secret";
    let result = connector
        .handle_configure(json!({
            "providers": [{
                "name": "litellm",
                "base_url": "https://litellm.flywheel.dev/v1",
                "api_key": secret_key,
                "models": [
                    {
                        "id": "openrouter/openai/gpt-4o",
                        "capabilities": ["vision", "tool_use"],
                        "context_window": 128000,
                        "cost_per_input_token": 0.000005,
                        "cost_per_output_token": 0.000015
                    },
                    {
                        "id": "openai/gpt-image-1",
                        "capabilities": ["vision"],
                        "context_window": 64000,
                        "cost_per_input_token": 0.00001,
                        "cost_per_output_token": 0.00004
                    }
                ]
            }]
        }))
        .await
        .unwrap();

    let provisioning = result["provisioning"].as_array().unwrap();
    assert_eq!(provisioning[0]["name"], "litellm");
    assert_eq!(provisioning[0]["network_ok"], true);
    assert_eq!(provisioning[0]["auth_mode"], "api_key");
    assert_eq!(provisioning[0]["models_ok"], true);

    let providers = connector
        .handle_invoke(json!({
            "operation": "llm-router.list_providers",
            "capability_token": "test",
            "input": {"include_models": true}
        }))
        .await
        .unwrap();
    let provider = &providers["providers"].as_array().unwrap()[0];
    assert_eq!(provider["name"], "litellm");
    assert_eq!(provider["passthrough_provider_models"], true);
    assert_eq!(provider["image_generation_provider"], true);
    assert_eq!(provider["models"][0]["id"], "openrouter/openai/gpt-4o");
    assert_eq!(provider["models"][1]["id"], "openai/gpt-image-1");
    assert_eq!(provider["models"][1]["cost_per_output_token"], 0.00004);

    let output = format!(
        "{}{}{}",
        serde_json::to_string(&result).unwrap(),
        serde_json::to_string(&providers).unwrap(),
        serde_json::to_string(&connector.handle_self_check().await.unwrap()).unwrap()
    );
    assert!(!output.contains(secret_key));
}

#[fcp_async_core::runtime::test]
async fn configure_litellm_gateway_accepts_credential_id_secretless() {
    let mut connector = LlmRouterConnector::new();
    let result = connector
        .handle_configure(json!({
            "providers": [{
                "name": "litellm",
                "base_url": "https://litellm.flywheel.dev",
                "credential_id": "litellm-egress-credential",
                "models": [{
                    "id": "openrouter/openai/gpt-4o",
                    "capabilities": ["vision"],
                    "context_window": 128000,
                    "cost_per_input_token": 0.000005,
                    "cost_per_output_token": 0.000015
                }]
            }]
        }))
        .await
        .unwrap();

    let provisioning = result["provisioning"].as_array().unwrap();
    assert_eq!(provisioning[0]["auth_mode"], "credential_id");
    assert_eq!(provisioning[0]["network_ok"], true);
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_litellm_missing_base_url() {
    let mut connector = LlmRouterConnector::new();
    let result = connector
        .handle_configure(json!({
            "providers": [{
                "name": "litellm",
                "api_key": "provider-key",
                "models": []
            }]
        }))
        .await;
    let err = result.unwrap_err().to_string();
    assert!(err.contains("missing base_url"));
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_litellm_unsafe_operator_base_urls() {
    for base_url in [
        "http://litellm.flywheel.dev",
        "https://localhost",
        "https://127.0.0.1",
        "https://10.0.0.1",
        "https://[fd00::1]",
        "https://litellm",
        "https://litellm.local",
        "https://user@litellm.flywheel.dev",
        "https://litellm.flywheel.dev:444",
        "https://litellm.flywheel.dev/proxy",
        "https://litellm.flywheel.dev/v1?proxy=1",
        "https://litellm.flywheel.dev/v1#fragment",
    ] {
        let mut connector = LlmRouterConnector::new();
        let result = connector
            .handle_configure(json!({
                "providers": [{
                    "name": "litellm",
                    "base_url": base_url,
                    "api_key": "provider-key",
                    "models": [{
                        "id": "openrouter/openai/gpt-4o",
                        "capabilities": [],
                        "context_window": 128000,
                        "cost_per_input_token": 0.000005,
                        "cost_per_output_token": 0.000015
                    }]
                }]
            }))
            .await;
        assert!(
            result.is_err(),
            "expected unsafe LiteLLM base_url to be rejected: {base_url}"
        );
    }
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_litellm_gateway_host_reserved_for_wrong_descriptor() {
    let mut connector = LlmRouterConnector::new();
    let result = connector
        .handle_configure(json!({
            "providers": [{
                "name": "litellm",
                "base_url": "https://ai-gateway.vercel.sh/v1",
                "api_key": "provider-key",
                "models": [{
                    "id": "openai/gpt-4o",
                    "capabilities": [],
                    "context_window": 128000,
                    "cost_per_input_token": 0.000005,
                    "cost_per_output_token": 0.000015
                }]
            }]
        }))
        .await;
    let err = result.unwrap_err().to_string();
    assert!(err.contains("reserved for descriptor(s) 'vercel-ai-gateway'"));
}

#[fcp_async_core::runtime::test]
async fn configure_long_tail_fixed_provider_catalog_entries() {
    let mut connector = LlmRouterConnector::new();
    let result = connector
        .handle_configure(json!({
            "providers": [
                {
                    "name": "deepseek",
                    "api_key": "deepseek-key",
                    "models": [{
                        "id": "deepseek-chat",
                        "capabilities": ["code"],
                        "context_window": 131072,
                        "cost_per_input_token": 0.00000028,
                        "cost_per_output_token": 0.00000042
                    }]
                },
                {
                    "name": "groq",
                    "api_key": "groq-key",
                    "models": [{
                        "id": "llama-3.3-70b-versatile",
                        "capabilities": ["code"],
                        "context_window": 131072,
                        "cost_per_input_token": 0.00000059,
                        "cost_per_output_token": 0.00000079
                    }]
                },
                {
                    "name": "xai",
                    "api_key": "xai-key",
                    "models": [{
                        "id": "grok-4-fast-reasoning",
                        "capabilities": ["vision"],
                        "context_window": 256000,
                        "cost_per_input_token": 0.000001,
                        "cost_per_output_token": 0.000005
                    }]
                },
                {
                    "name": "openrouter",
                    "api_key": "openrouter-key",
                    "models": [{
                        "id": "anthropic/claude-sonnet-4",
                        "capabilities": ["vision", "tool_use"],
                        "context_window": 200000,
                        "cost_per_input_token": 0.000003,
                        "cost_per_output_token": 0.000015
                    }]
                },
                {
                    "name": "moonshot",
                    "api_key": "moonshot-key",
                    "models": [{
                        "id": "kimi-k2.6",
                        "capabilities": ["code"],
                        "context_window": 262144,
                        "cost_per_input_token": 0.000001,
                        "cost_per_output_token": 0.000003
                    }]
                },
                {
                    "name": "kimi-coding",
                    "api_key": "kimi-key",
                    "models": [{
                        "id": "kimi-k2.5",
                        "capabilities": ["code"],
                        "context_window": 262144,
                        "cost_per_input_token": 0.000001,
                        "cost_per_output_token": 0.000003
                    }]
                },
                {
                    "name": "qwen",
                    "api_key": "qwen-key",
                    "models": [{
                        "id": "qwen3.5-plus",
                        "capabilities": ["vision"],
                        "context_window": 131072,
                        "cost_per_input_token": 0.000001,
                        "cost_per_output_token": 0.000004
                    }]
                },
                {
                    "name": "together",
                    "api_key": "together-key",
                    "models": [{
                        "id": "moonshotai/Kimi-K2.5",
                        "capabilities": ["vision"],
                        "context_window": 262144,
                        "cost_per_input_token": 0.0000005,
                        "cost_per_output_token": 0.0000028
                    }]
                }
            ]
        }))
        .await
        .unwrap();

    let provisioning = result["provisioning"].as_array().unwrap();
    assert_eq!(provisioning.len(), 8);
    for provider in provisioning {
        assert_eq!(provider["network_ok"], true);
        assert_eq!(provider["auth_mode"], "api_key");
    }

    let providers = connector
        .handle_invoke(json!({
            "operation": "llm-router.list_providers",
            "capability_token": "test",
            "input": {"include_models": true}
        }))
        .await
        .unwrap();
    let providers = providers["providers"].as_array().unwrap();
    let xai = providers.iter().find(|p| p["name"] == "xai").unwrap();
    assert_eq!(xai["models"][0]["id"], "grok-4-fast");
    assert_eq!(xai["image_generation_provider"], true);

    let openrouter = providers
        .iter()
        .find(|p| p["name"] == "openrouter")
        .unwrap();
    assert_eq!(openrouter["passthrough_provider_models"], true);
    assert_eq!(openrouter["image_generation_provider"], true);
    assert_eq!(openrouter["models"][0]["id"], "anthropic/claude-sonnet-4");

    let kimi = providers
        .iter()
        .find(|p| p["name"] == "kimi-coding")
        .unwrap();
    assert_eq!(kimi["models"][0]["id"], "kimi-k2.5");
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_fixed_long_tail_base_url_override() {
    let mut connector = LlmRouterConnector::new();
    let result = connector
        .handle_configure(json!({
            "providers": [{
                "name": "groq",
                "base_url": "https://api.groq.com/v1",
                "api_key": "groq-key",
                "models": []
            }]
        }))
        .await;
    let err = result.unwrap_err().to_string();
    assert!(err.contains("fixed gateway-provider descriptors do not accept base_url overrides"));
}

#[fcp_async_core::runtime::test]
async fn configure_rejects_disallowed_host() {
    let mut connector = LlmRouterConnector::new();
    let result = connector
        .handle_configure(json!({
            "providers": [{
                "name": "evil",
                "base_url": "https://evil.example.com",
                "api_key": "key-123",
                "models": [{
                    "id": "evil-model",
                    "capabilities": [],
                    "context_window": 4096,
                    "cost_per_input_token": 0.0001,
                    "cost_per_output_token": 0.0001
                }]
            }]
        }))
        .await;
    assert!(result.is_err());
}

#[fcp_async_core::runtime::test]
async fn doctor_unconfigured_is_unhealthy() {
    let connector = LlmRouterConnector::new();
    let result = connector.handle_doctor().await.unwrap();
    assert_eq!(result["status"], "unhealthy");
    let checks = result["checks"].as_array().unwrap();
    assert!(!checks.is_empty());
    assert_eq!(checks[0]["name"], "configuration");
    assert_eq!(checks[0]["passed"], false);
}

// ─── Redaction tests (no secret/PII leakage) ────────────────────────────────

#[fcp_async_core::runtime::test]
async fn configure_response_does_not_leak_api_keys() {
    let mut connector = LlmRouterConnector::new();
    let secret_key = "sk-secret-1234567890abcdef";
    let result = connector
        .handle_configure(json!({
            "providers": [{
                "name": "anthropic",
                "base_url": "https://api.anthropic.com",
                "api_key": secret_key,
                "models": [{
                    "id": "claude-sonnet-4",
                    "capabilities": ["code"],
                    "context_window": 200000,
                    "cost_per_input_token": 0.000003,
                    "cost_per_output_token": 0.000015
                }]
            }]
        }))
        .await
        .unwrap();

    // Serialized response must not contain the raw API key
    let response_str = serde_json::to_string(&result).unwrap();
    assert!(
        !response_str.contains(secret_key),
        "API key leaked in configure response"
    );
    assert!(!response_str.contains("sk-secret"));
    assert!(!response_str.contains("cdef"));
    assert!(response_str.contains("\"auth_mode\":\"api_key\""));
}

#[fcp_async_core::runtime::test]
async fn error_messages_do_not_leak_api_keys() {
    let mut connector = LlmRouterConnector::new();
    let secret_key = "sk-topSecret789xyz";
    // Configure with valid key
    connector
        .handle_configure(json!({
            "providers": [{
                "name": "anthropic",
                "base_url": "https://api.anthropic.com",
                "api_key": secret_key,
                "models": [{
                    "id": "claude-sonnet-4",
                    "capabilities": ["code"],
                    "context_window": 200000,
                    "cost_per_input_token": 0.000003,
                    "cost_per_output_token": 0.000015
                }]
            }],
            "budget": {"budget_usd": 0.0, "enforcement": "hard"}
        }))
        .await
        .unwrap();

    // Try to route — budget exceeded
    let result = connector
        .handle_invoke(json!({
            "operation": "llm-router.route",
            "capability_token": "test",
            "input": {"messages": [{"role": "user", "content": "hello"}]}
        }))
        .await;

    // Error message must not contain the API key
    if let Err(e) = result {
        let err_str = format!("{e:?}");
        assert!(
            !err_str.contains(secret_key),
            "API key leaked in error message"
        );
    }
}

#[fcp_async_core::runtime::test]
async fn doctor_does_not_leak_full_api_keys() {
    let mut connector = LlmRouterConnector::new();
    let secret_key = "sk-my-super-secret-key-9999";
    connector
        .handle_configure(json!({
            "providers": [{
                "name": "anthropic",
                "base_url": "https://api.anthropic.com",
                "api_key": secret_key,
                "models": [{
                    "id": "claude-sonnet-4",
                    "capabilities": ["code"],
                    "context_window": 200000,
                    "cost_per_input_token": 0.000003,
                    "cost_per_output_token": 0.000015
                }]
            }]
        }))
        .await
        .unwrap();

    let doctor = connector.handle_doctor().await.unwrap();
    let doctor_str = serde_json::to_string(&doctor).unwrap();
    assert!(
        !doctor_str.contains(secret_key),
        "Full API key leaked in doctor output"
    );
    assert!(!doctor_str.contains("sk-my"));
    assert!(!doctor_str.contains("9999"));
    assert!(doctor_str.contains("api_key:[redacted]"));
}

#[fcp_async_core::runtime::test]
async fn self_check_does_not_leak_api_keys() {
    let mut connector = LlmRouterConnector::new();
    let secret_key = "sk-self-check-secret-314159";
    connector
        .handle_configure(json!({
            "providers": [{
                "name": "anthropic",
                "base_url": "https://api.anthropic.com",
                "api_key": secret_key,
                "models": [{
                    "id": "claude-sonnet-4",
                    "capabilities": ["code"],
                    "context_window": 200000,
                    "cost_per_input_token": 0.000003,
                    "cost_per_output_token": 0.000015
                }]
            }]
        }))
        .await
        .unwrap();

    let self_check = connector.handle_self_check().await.unwrap();
    let self_check_str = serde_json::to_string(&self_check).unwrap();
    assert!(!self_check_str.contains(secret_key));
    assert!(!self_check_str.contains("sk-self"));
    assert!(!self_check_str.contains("314159"));
    assert!(self_check_str.contains("\"auth_mode\":\"api_key\""));
}

// ─── Error taxonomy + retry semantics ────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn budget_exceeded_is_capability_denied() {
    let mut connector = LlmRouterConnector::new();
    connector
        .handle_configure(json!({
            "providers": [{
                "name": "anthropic",
                "base_url": "https://api.anthropic.com",
                "api_key": "test-key",
                "models": [{
                    "id": "claude-sonnet-4",
                    "capabilities": ["code"],
                    "context_window": 200000,
                    "cost_per_input_token": 0.000003,
                    "cost_per_output_token": 0.000015
                }]
            }],
            "budget": {"budget_usd": 0.0, "enforcement": "hard"}
        }))
        .await
        .unwrap();

    let result = connector
        .handle_invoke(json!({
            "operation": "llm-router.route",
            "capability_token": "test",
            "input": {"messages": [{"role": "user", "content": "hello"}]}
        }))
        .await;

    assert!(result.is_err());
    // Budget exceeded should map to CapabilityDenied, not Internal
    let err = result.unwrap_err();
    let err_str = format!("{err:?}");
    assert!(
        err_str.contains("CapabilityDenied"),
        "Budget exceeded should be CapabilityDenied, got: {err_str}"
    );
}

#[fcp_async_core::runtime::test]
async fn no_capability_match_is_invalid_request() {
    let mut connector = configured_connector().await;

    // Use "math" — a valid ModelCapability that no test provider has configured
    let result = connector
        .handle_invoke(json!({
            "operation": "llm-router.route",
            "capability_token": "test",
            "input": {
                "messages": [{"role": "user", "content": "hello"}],
                "required_capabilities": ["math"]
            }
        }))
        .await;

    // Should fail (no provider has "math" capability)
    // but gracefully, not panic
    assert!(result.is_err());
}

// ─── Adversarial inputs ──────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn route_with_malformed_messages() {
    let mut connector = configured_connector().await;

    // Messages without content field
    let result = connector
        .handle_invoke(json!({
            "operation": "llm-router.route",
            "capability_token": "test",
            "input": {
                "messages": [{"role": "user"}]
            }
        }))
        .await;

    // Should succeed (routing doesn't require content in every message)
    // or fail gracefully without panic
    assert!(result.is_ok() || result.is_err());
}

#[fcp_async_core::runtime::test]
async fn route_with_null_content() {
    let mut connector = configured_connector().await;

    let result = connector
        .handle_invoke(json!({
            "operation": "llm-router.route",
            "capability_token": "test",
            "input": {
                "messages": [{"role": "user", "content": null}]
            }
        }))
        .await;

    // Must not panic
    assert!(result.is_ok() || result.is_err());
}

#[fcp_async_core::runtime::test]
async fn route_with_very_long_content() {
    let mut connector = configured_connector().await;

    let long_content = "x".repeat(1_000_000);
    let result = connector
        .handle_invoke(json!({
            "operation": "llm-router.route",
            "capability_token": "test",
            "input": {
                "messages": [{"role": "user", "content": long_content}]
            }
        }))
        .await;

    // Should succeed (token estimation handles long content)
    assert!(result.is_ok());
    let val = result.unwrap();
    assert!(val["usage"]["input_tokens"].as_u64().unwrap() > 100_000);
}

#[fcp_async_core::runtime::test]
async fn estimate_cost_with_invalid_provider_filter() {
    let mut connector = configured_connector().await;

    let result = connector
        .handle_invoke(json!({
            "operation": "llm-router.estimate_cost",
            "capability_token": "test",
            "input": {
                "messages": [{"role": "user", "content": "hello"}],
                "providers": ["nonexistent_provider"]
            }
        }))
        .await
        .unwrap();

    // Should return empty estimates (no matching providers)
    let estimates = result["estimates"].as_array().unwrap();
    assert!(estimates.is_empty());
}

#[fcp_async_core::runtime::test]
async fn route_with_invalid_strategy_uses_default() {
    let mut connector = configured_connector().await;

    let result = connector
        .handle_invoke(json!({
            "operation": "llm-router.route",
            "capability_token": "test",
            "input": {
                "messages": [{"role": "user", "content": "hello"}],
                "strategy": "not_a_real_strategy"
            }
        }))
        .await;

    // Invalid strategy string should fall back to default (cost)
    assert!(result.is_ok());
    let val = result.unwrap();
    assert_eq!(val["routing_decision"]["strategy_used"], "cost");
}

// ─── Schema & bounds ─────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn all_operations_have_schemas() {
    let connector = LlmRouterConnector::new();
    let result = connector.handle_introspect().await.unwrap();
    let ops = result["operations"].as_array().unwrap();

    for op in ops {
        let id = op["id"].as_str().unwrap();
        assert!(
            op.get("input_schema").is_some(),
            "Operation {id} missing input_schema"
        );
        assert!(
            op.get("output_schema").is_some(),
            "Operation {id} missing output_schema"
        );
    }
}

#[fcp_async_core::runtime::test]
async fn operations_have_correct_risk_levels() {
    let connector = LlmRouterConnector::new();
    let result = connector.handle_introspect().await.unwrap();
    let ops = result["operations"].as_array().unwrap();

    for op in ops {
        let id = op["id"].as_str().unwrap();
        let risk = op["risk_level"].as_str().unwrap();
        // All router operations should be low or medium (serde serializes lowercase)
        assert!(
            risk == "low" || risk == "medium",
            "Operation {id} has unexpected risk level: {risk}"
        );
    }
}

#[fcp_async_core::runtime::test]
async fn usage_accumulates_correctly() {
    let mut connector = configured_connector().await;

    // Route 3 requests
    for _ in 0..3 {
        connector
            .handle_invoke(json!({
                "operation": "llm-router.route",
                "capability_token": "test",
                "input": {"messages": [{"role": "user", "content": "Hello world"}]}
            }))
            .await
            .unwrap();
    }

    let usage = connector
        .handle_invoke(json!({
            "operation": "llm-router.get_usage",
            "capability_token": "test",
            "input": {}
        }))
        .await
        .unwrap();

    assert_eq!(usage["requests_total"], 3);
    assert!(usage["total_cost_usd"].as_f64().unwrap() > 0.0);
    assert!(usage["total_input_tokens"].as_u64().unwrap() > 0);
    assert!(usage["total_output_tokens"].as_u64().unwrap() > 0);
}

#[fcp_async_core::runtime::test]
async fn budget_remaining_decreases_after_route() {
    let mut connector = LlmRouterConnector::new();
    connector
        .handle_configure(json!({
            "providers": [{
                "name": "anthropic",
                "base_url": "https://api.anthropic.com",
                "api_key": "test-key",
                "models": [{
                    "id": "claude-sonnet-4",
                    "capabilities": ["code"],
                    "context_window": 200000,
                    "cost_per_input_token": 0.000003,
                    "cost_per_output_token": 0.000015
                }]
            }],
            "budget": {"budget_usd": 100.0, "enforcement": "soft"}
        }))
        .await
        .unwrap();

    // Get initial budget
    let budget_before = connector
        .handle_invoke(json!({
            "operation": "llm-router.get_budget",
            "capability_token": "test",
            "input": {}
        }))
        .await
        .unwrap();
    let remaining_before = budget_before["remaining_usd"].as_f64().unwrap();

    // Route a request
    connector
        .handle_invoke(json!({
            "operation": "llm-router.route",
            "capability_token": "test",
            "input": {"messages": [{"role": "user", "content": "Hello"}]}
        }))
        .await
        .unwrap();

    // Get budget after
    let budget_after = connector
        .handle_invoke(json!({
            "operation": "llm-router.get_budget",
            "capability_token": "test",
            "input": {}
        }))
        .await
        .unwrap();
    let remaining_after = budget_after["remaining_usd"].as_f64().unwrap();

    assert!(remaining_after < remaining_before);
}

// ─── Idempotency ─────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn configure_is_idempotent() {
    let mut connector = LlmRouterConnector::new();

    // Configure twice with same config
    let r1 = connector.handle_configure(test_config()).await.unwrap();
    let r2 = connector.handle_configure(test_config()).await.unwrap();

    assert_eq!(r1["status"], r2["status"]);
    assert_eq!(r1["providers"], r2["providers"]);
}

#[fcp_async_core::runtime::test]
async fn introspect_is_deterministic() {
    let connector = LlmRouterConnector::new();

    let r1 = connector.handle_introspect().await.unwrap();
    let r2 = connector.handle_introspect().await.unwrap();

    // Same operations in same order
    assert_eq!(r1["operations"], r2["operations"]);
}
