//! Environment-gated live verification for the `Mixpanel` connector.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc
)]

use std::env;

use fcp_mixpanel::client::{MixpanelAuth, MixpanelClient};
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const USERNAME_ENV: &str = "MIXPANEL_SANDBOX_USERNAME";
const SECRET_ENV: &str = "MIXPANEL_SANDBOX_SECRET";
const PROJECT_ID_ENV: &str = "MIXPANEL_SANDBOX_PROJECT_ID";
const BASE_URL_ENV: &str = "MIXPANEL_SANDBOX_BASE_URL";
const NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const DEFAULT_BASE_URL: &str = "https://mixpanel.com/api/2.0";
const OP_LIST_FUNNELS: &str = "mixpanel.funnels.list";

fn env_value(name: &'static str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn gate_enabled() -> bool {
    env_value(LIVE_GATE_ENV).is_some_and(|value| {
        value == "1"
            || value.eq_ignore_ascii_case("true")
            || value.eq_ignore_ascii_case("yes")
            || value.eq_ignore_ascii_case("on")
    })
}

fn missing_env() -> Vec<&'static str> {
    [USERNAME_ENV, SECRET_ENV, PROJECT_ID_ENV, NAMESPACE_ENV]
        .into_iter()
        .filter(|name| env_value(name).is_none())
        .collect()
}

fn evidence_summary(missing: &[&'static str], base_url_defaulted: bool) -> Value {
    let loaded_keys = [USERNAME_ENV, SECRET_ENV, PROJECT_ID_ENV, NAMESPACE_ENV]
        .into_iter()
        .filter(|name| env_value(name).is_some())
        .collect::<Vec<_>>();
    let secrets_loaded = [USERNAME_ENV, SECRET_ENV]
        .into_iter()
        .filter(|name| env_value(name).is_some())
        .count();
    let secrets_missing = [USERNAME_ENV, SECRET_ENV]
        .into_iter()
        .filter(|name| env_value(name).is_none())
        .collect::<Vec<_>>();
    json!({
        "manifest": {
            "connector": "mixpanel",
            "provider": "Mixpanel sandbox",
            "tier": "sandbox_required",
            "secret_count": 2,
            "required_env_var_count": 2,
            "defaulted_env_var_count": 1,
            "budget_usd": 0.01,
            "cleanup_strategy": {"kind": "prefix_delete", "uses_synthetic_tenant": true},
            "rate_limits": {"max_rps": 1.0, "backoff_on_429": true, "min_delay_ms": 1000},
            "account_setup_configured": true,
            "synthetic_tenant_expected": true,
            "metadata_keys": []
        },
        "env_vars": {
            "complete": missing.is_empty(),
            "loaded_count": loaded_keys.len(),
            "loaded_keys": loaded_keys,
            "missing": missing,
            "defaults_used": if base_url_defaulted { vec![BASE_URL_ENV] } else { Vec::new() }
        },
        "secrets_loaded": secrets_loaded,
        "secrets_missing": secrets_missing,
        "tenant_prefix": "fcp-test-mixpanel",
        "ready": missing.is_empty(),
        "budget": {
            "budget_max_usd": 0.01,
            "total_spent_usd": 0.0,
            "remaining_usd": 0.01,
            "api_call_count": 0,
            "within_limits": true,
            "alert_level": "ok"
        },
        "cleanup_expectations": {"kind": "prefix_delete", "uses_synthetic_tenant": true}
    })
}

fn emit_live_jsonl(status: &str, reason: &str, observed_count: usize, evidence: &Value) {
    eprintln!(
        "MIXPANEL_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "mixpanel_live_sandbox_verification",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": [USERNAME_ENV, SECRET_ENV],
            "required_env": [PROJECT_ID_ENV, NAMESPACE_ENV],
            "defaulted_env": BASE_URL_ENV,
            "operation": OP_LIST_FUNNELS,
            "status": status,
            "provider": "Mixpanel sandbox",
            "environment": "sandbox",
            "resource_class": "funnel_listing",
            "observed_count": observed_count,
            "call_ceiling": 1,
            "rate_limit_guidance": "Performs one read-only funnel listing against the sandbox project.",
            "mutation_expected": false,
            "cleanup_strategy": "prefix_delete",
            "provider_resource_ids_logged": false,
            "secret_values_logged": false,
            "skip_reason": if status == "skipped" { Some(reason) } else { None },
            "fcp_error_mapping": if status == "failed" { Some(reason) } else { None },
            "evidence": evidence,
        })
    );
}

#[fcp_async_core::runtime::test]
async fn mixpanel_live_sandbox_funnel_listing_or_structured_skip_jsonl() {
    let base_url = env_value(BASE_URL_ENV).unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
    let base_url_defaulted = env_value(BASE_URL_ENV).is_none();
    let missing = missing_env();
    let evidence = evidence_summary(&missing, base_url_defaulted);
    if !gate_enabled() || !missing.is_empty() {
        let reason = if gate_enabled() {
            format!(
                "missing required sandbox environment: {}",
                missing.join(", ")
            )
        } else {
            format!("Live tier 'sandbox_required' not enabled. Set {LIVE_GATE_ENV}=1 to run.")
        };
        emit_live_jsonl("skipped", &reason, 0, &evidence);
        return;
    }

    let client = configured_client(&base_url);
    match client.list_funnels().await {
        Ok(value) => {
            let observed_count = value
                .as_array()
                .map_or_else(
                    || value.get("funnels").and_then(serde_json::Value::as_array),
                    Some,
                )
                .map_or(0, std::vec::Vec::len);
            emit_live_jsonl(
                "passed",
                "",
                observed_count,
                &json!({
                    "environment": evidence,
                    "operation_result": "mixpanel.funnels.list completed",
                }),
            );
        }
        Err(error) => {
            emit_live_jsonl("failed", &error.to_string(), 0, &evidence);
            panic!("Mixpanel sandbox funnel listing failed: {error}");
        }
    }
    client.shutdown();
}

fn configured_client(base_url: &str) -> MixpanelClient {
    MixpanelClient::new(
        MixpanelAuth::ServiceAccount {
            username: env_value(USERNAME_ENV).expect("username env is ready"),
            secret: env_value(SECRET_ENV).expect("secret env is ready"),
        },
        &env_value(PROJECT_ID_ENV).expect("project id env is ready"),
        Some(base_url),
    )
    .expect("construct Mixpanel live client")
}
