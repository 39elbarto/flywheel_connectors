//! Environment-gated sandbox verification for the `Zendesk` connector.

#![allow(
    clippy::expect_used,
    clippy::future_not_send,
    clippy::missing_panics_doc,
    clippy::panic,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use chrono::{Duration as ChronoDuration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_prelude::CapabilityConstraints;
use fcp_testkit::live_suite::{CleanupStrategy, EnvironmentManifest, LiveEnvironment, LiveGate};
use fcp_zendesk::connector::ZendeskConnector;
use serde_json::{Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_SANDBOX";
const SUBDOMAIN_ENV: &str = "ZENDESK_SANDBOX_SUBDOMAIN";
const EMAIL_ENV: &str = "ZENDESK_SANDBOX_EMAIL";
const API_TOKEN_ENV: &str = "ZENDESK_SANDBOX_API_TOKEN";
const NAMESPACE_ENV: &str = "FCP_SANDBOX_RUN_NAMESPACE";
const OP_SEARCH_TICKETS: &str = "zendesk.search_tickets";

fn manifest() -> EnvironmentManifest {
    EnvironmentManifest::sandbox("zendesk", "Zendesk sandbox")
        .with_env_secret(
            "api_token",
            API_TOKEN_ENV,
            "Zendesk API token scoped to the sandbox account",
        )
        .with_env_var(SUBDOMAIN_ENV, "Zendesk sandbox subdomain")
        .with_env_var(EMAIL_ENV, "Zendesk sandbox agent email for token auth")
        .with_env_var(
            NAMESPACE_ENV,
            "Shared namespace recorded in evidence for any sandbox-side artifacts",
        )
        .with_account_setup(
            "Use a dedicated Zendesk sandbox or development account. This suite performs one read-only ticket search by default; write-path proof belongs in a dedicated namespaced ticket flow.",
        )
        .with_budget(0.01)
        .with_cleanup(CleanupStrategy::PrefixDelete)
        .with_rate_limits(0.5, true)
}

fn emit_live_jsonl(status: &str, reason: &str, observed_count: usize, evidence: &Value) {
    eprintln!(
        "ZENDESK_LIVE_SANDBOX_JSONL {}",
        json!({
            "event": "zendesk_live_sandbox_verification",
            "fixture_mode": "live",
            "suite_class": "sandbox_required",
            "gate_env_var": LIVE_GATE_ENV,
            "required_secret_env": API_TOKEN_ENV,
            "required_env": [SUBDOMAIN_ENV, EMAIL_ENV, NAMESPACE_ENV],
            "operation": OP_SEARCH_TICKETS,
            "status": status,
            "provider": "Zendesk sandbox",
            "environment": "sandbox",
            "resource_class": "ticket_search",
            "observed_count": observed_count,
            "call_ceiling": 1,
            "rate_limit_guidance": "Performs one read-only ticket search against the sandbox account.",
            "mutation_expected": false,
            "cleanup_strategy": "prefix_delete",
            "provider_resource_ids_logged": false,
            "secret_values_logged": false,
            "subdomain_logged": false,
            "email_logged": false,
            "ticket_subjects_logged": false,
            "skip_reason": if status == "skipped" { Some(reason) } else { None },
            "fcp_error_mapping": if status == "failed" { Some(reason) } else { None },
            "evidence": evidence,
        })
    );
}

fn skip_reason(gate: &LiveGate, env: &LiveEnvironment) -> String {
    if gate.is_enabled() {
        env.problems().join("; ")
    } else {
        gate.skip_reason()
    }
}

#[fcp_async_core::runtime::test]
async fn zendesk_live_sandbox_ticket_search_or_structured_skip_jsonl() {
    let gate = LiveGate::sandbox();
    let env = LiveEnvironment::from_manifest(manifest());
    if !gate.is_enabled() || !env.is_ready() {
        emit_live_jsonl(
            "skipped",
            &skip_reason(&gate, &env),
            0,
            &env.evidence_summary(),
        );
        return;
    }

    let (connector, signing_key) = configured_connector(&env).await;
    let instance_id = connector.instance_id().to_string();
    match connector
        .handle_invoke(json!({
            "operation": OP_SEARCH_TICKETS,
            "input": {
                "query": "status<closed",
                "per_page": 1
            },
            "capability_token": capability_token(&signing_key, &instance_id, OP_SEARCH_TICKETS)
        }))
        .await
    {
        Ok(value) => {
            let observed_count = value["results"].as_array().map_or(0, Vec::len);
            emit_live_jsonl(
                "passed",
                "",
                observed_count,
                &json!({
                    "environment": env.evidence_summary(),
                    "operation_result": "search_tickets completed",
                }),
            );
        }
        Err(error) => {
            emit_live_jsonl("failed", &error.to_string(), 0, &env.evidence_summary());
            panic!("Zendesk sandbox ticket search failed: {error}");
        }
    }
    connector
        .handle_shutdown(json!({}))
        .await
        .expect("shutdown live connector");
}

async fn configured_connector(env: &LiveEnvironment) -> (ZendeskConnector, Ed25519SigningKey) {
    let mut connector = ZendeskConnector::new();
    connector
        .handle_configure(json!({
            "subdomain": env.env_vars.get(SUBDOMAIN_ENV).expect("subdomain env is ready"),
            "email": env.env_vars.get(EMAIL_ENV).expect("email env is ready"),
            "api_token": env.secrets.require("api_token")
        }))
        .await
        .expect("configure live connector");

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0_u8; 32],
            "capabilities_requested": ["zendesk.read"]
        }))
        .await
        .expect("handshake live connector");
    (connector, signing_key)
}

fn capability_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &str,
    operation: &'static str,
) -> fcp_core::CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id("zendesk.read")
        .zone_id("z:work")
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .target_instance(instance_id)
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("sign capability token");
    fcp_core::CapabilityToken::from_raw(cose)
}
