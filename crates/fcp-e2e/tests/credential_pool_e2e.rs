//! Credential-pool E2E evidence harness for `flywheel_connectors-4kw5f.7.9`.
//!
//! This deterministic harness exercises the real `fcp-host` credential-pool
//! registry and emits redaction-safe JSONL evidence for the connector-boundary
//! gap still tracked by parent bead `flywheel_connectors-4kw5f.7`. It does not
//! claim live `fcp-host` + Groq process spawning; instead it records that live
//! boundary as a structured skip unless that runner is added later.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration as StdDuration;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_host::{
    CredentialCooldown, CredentialErrorKind, CredentialMutationOutcome,
    CredentialPoolAuditOperation, CredentialPoolError, CredentialPoolKey, CredentialPoolRegistry,
    CredentialPoolStrategy, CredentialSource, CredentialUpsertMode, PoolExhaustedBehavior,
    PooledCredential, ProviderKey,
};
use fcp_prelude::{CredentialId, ZoneId};
use serde_json::{Value, json};

const SCHEMA: &str = "fcp.credential_pool.e2e.v1";
const ARTIFACT_PATH: &str = "target/fcp-credential-pool/credential-pool-e2e.jsonl";
const REQUEST_COUNT: usize = 100;

const MATERIAL_ALPHA: &str = "pool-material-alpha";
const MATERIAL_BETA: &str = "pool-material-beta";
const MATERIAL_GAMMA: &str = "pool-material-gamma";

#[test]
fn credential_pool_e2e_emits_redacted_round_robin_cooldown_and_exhaustion_evidence() {
    let started = Utc::now();
    let key = pool_key();
    let mut registry = registry_with_three_groq_credentials(&key);
    registry
        .set_exhausted_behavior(&key, PoolExhaustedBehavior::Wait)
        .expect("pool exhausted behavior should update");

    let mut records = Vec::new();
    records.push(scenario_event(
        "scenario_started",
        "setup",
        "pass",
        json!({
            "scenario_id": "credential-pool-groq-round-robin-cooldown",
            "operation": "chat.completions",
            "request_count": REQUEST_COUNT,
            "parallel_threads": REQUEST_COUNT,
            "strategy": "round_robin",
            "live_boundary": "structured_skip_recorded"
        }),
    ));

    let (distribution, mut lease_records) =
        run_parallel_round_robin_requests(registry, key.clone());
    records.append(&mut lease_records);

    assert_eq!(
        distribution.len(),
        3,
        "all 3 credentials must receive traffic"
    );
    assert_eq!(distribution[&credential_id(1)], 34);
    assert_eq!(distribution[&credential_id(2)], 33);
    assert_eq!(distribution[&credential_id(3)], 33);
    records.push(scenario_event(
        "round_robin_distribution_verified",
        "verify",
        "pass",
        json!({
            "distribution": distribution
                .iter()
                .map(|(credential_id, count)| json!({
                    "credential_id": credential_id.to_string(),
                    "count": count
                }))
                .collect::<Vec<_>>(),
            "assertion": "100 requests distributed 34/33/33 across 3 credentials"
        }),
    ));

    let mut registry = registry_with_three_groq_credentials(&key);
    registry
        .set_exhausted_behavior(&key, PoolExhaustedBehavior::Wait)
        .expect("pool exhausted behavior should update");
    advance_round_robin_cursor(&mut registry, &key, REQUEST_COUNT);
    append_cooldown_reroute_and_recovery_records(&mut registry, &key, &mut records);
    append_pool_exhaustion_record(&mut registry, &key, &mut records);
    append_audit_receipts(&registry, &mut records);
    records.push(live_boundary_skip_record());
    records.push(scenario_event(
        "scenario_completed",
        "verify",
        "pass",
        json!({
            "duration_ms": (Utc::now() - started).num_milliseconds().max(0),
            "artifact_path": ARTIFACT_PATH
        }),
    ));

    let jsonl = write_jsonl_artifact(&records);
    assert_required_events_present(&jsonl);
    assert_redaction_invariants(&jsonl);
    assert_eq!(fcp_e2e::scan_log_jsonl(&jsonl).error_count, 0);
}

fn run_parallel_round_robin_requests(
    registry: CredentialPoolRegistry,
    key: CredentialPoolKey,
) -> (BTreeMap<CredentialId, u32>, Vec<Value>) {
    let registry = Arc::new(Mutex::new(registry));
    let handles = (0..REQUEST_COUNT)
        .map(|request_index| {
            let registry = Arc::clone(&registry);
            let key = key.clone();
            thread::spawn(move || {
                let now = Utc::now();
                let mut registry = registry.lock().expect("credential pool registry lock");
                let lease = registry.acquire(&key, now).expect("lease should acquire");
                let view = registry
                    .redacted_view(&key, now)
                    .expect("redacted view should exist");
                let active_leases_for_cred = view
                    .entries
                    .iter()
                    .find(|entry| entry.credential_id == lease.credential_id)
                    .map(|entry| entry.active_leases)
                    .expect("leased credential should be in redacted view");
                let acquired = lease_event(
                    "credential_lease_acquired",
                    "execute",
                    "pass",
                    &key,
                    lease.credential_id,
                    json!({
                        "request_index": request_index,
                        "operation": "chat.completions",
                        "strategy": "round_robin",
                        "active_leases_for_cred": active_leases_for_cred
                    }),
                );
                let released_id = registry
                    .release(&key, lease.token)
                    .expect("lease should release");
                assert_eq!(released_id, lease.credential_id);
                let released = lease_event(
                    "credential_lease_released",
                    "execute",
                    "pass",
                    &key,
                    released_id,
                    json!({
                        "request_index": request_index,
                        "operation": "chat.completions",
                        "outcome": "success"
                    }),
                );
                (released_id, vec![acquired, released])
            })
        })
        .collect::<Vec<_>>();

    let mut distribution = BTreeMap::new();
    let mut records = Vec::new();
    for handle in handles {
        let (credential_id, mut events) = handle.join().expect("request thread should not panic");
        *distribution.entry(credential_id).or_insert(0) += 1;
        records.append(&mut events);
    }

    (distribution, records)
}

fn append_cooldown_reroute_and_recovery_records(
    registry: &mut CredentialPoolRegistry,
    key: &CredentialPoolKey,
    records: &mut Vec<Value>,
) {
    let now = Utc::now();
    let rate_limited = registry
        .acquire(key, now)
        .expect("next lease should target credential 2 after 100 round-robin requests");
    assert_eq!(rate_limited.credential_id, credential_id(2));
    records.push(lease_event(
        "credential_lease_acquired",
        "execute",
        "pass",
        key,
        rate_limited.credential_id,
        json!({
            "operation": "chat.completions",
            "strategy": "round_robin",
            "injected_provider_status": 429
        }),
    ));
    let cooldowned_id = registry
        .report_error(
            key,
            rate_limited.token,
            CredentialErrorKind::RateLimited,
            Some(StdDuration::from_secs(2)),
            now,
        )
        .expect("rate limit should report and release");
    assert_eq!(cooldowned_id, credential_id(2));
    records.push(lease_event(
        "credential_lease_released",
        "execute",
        "pass",
        key,
        cooldowned_id,
        json!({
            "operation": "chat.completions",
            "outcome": "error",
            "error_kind": "rate_limited",
            "provider_error_body_logged": false
        }),
    ));

    let cooldown_until = cooldown_until_for(registry, key, cooldowned_id, now);
    records.push(lease_event(
        "credential_cooldown_set",
        "verify",
        "pass",
        key,
        cooldowned_id,
        json!({
            "until_unix": cooldown_until.timestamp(),
            "reason": "rate_limited",
            "retry_after_seconds": 2
        }),
    ));

    let rerouted = registry
        .acquire(key, now)
        .expect("pool should route around cooldowned credential");
    assert_ne!(
        rerouted.credential_id, cooldowned_id,
        "cooldowned credential must not receive the next request"
    );
    let rerouted_id = registry
        .release(key, rerouted.token)
        .expect("rerouted lease should release");
    records.push(lease_event(
        "credential_lease_released",
        "verify",
        "pass",
        key,
        rerouted_id,
        json!({
            "operation": "chat.completions",
            "outcome": "success",
            "rerouted_around_credential_id": cooldowned_id.to_string()
        }),
    ));

    let recovered_ids = acquire_three_after(
        registry,
        key,
        cooldown_until + ChronoDuration::milliseconds(1),
    );
    assert!(
        recovered_ids.contains(&cooldowned_id),
        "credential 2 should be selectable again after retry-after cooldown"
    );
    records.push(lease_event(
        "credential_cooldown_recovered",
        "verify",
        "pass",
        key,
        cooldowned_id,
        json!({
            "operation": "chat.completions",
            "recovery_window_checked": true
        }),
    ));
}

fn append_pool_exhaustion_record(
    registry: &mut CredentialPoolRegistry,
    key: &CredentialPoolKey,
    records: &mut Vec<Value>,
) {
    let now = Utc::now();
    let until = now + ChronoDuration::seconds(5);
    for id in [credential_id(1), credential_id(2), credential_id(3)] {
        registry
            .set_cooldown(key, id, Some(CredentialCooldown::Until { until }))
            .expect("manual cooldown should apply");
    }

    let error = registry
        .acquire(key, now)
        .expect_err("wait-mode exhausted pool should surface deterministic wait advice");
    let available_at = match error {
        CredentialPoolError::PoolWaitRequired { available_at, .. } => available_at,
        other => {
            assert!(
                matches!(other, CredentialPoolError::PoolWaitRequired { .. }),
                "expected PoolWaitRequired"
            );
            now
        }
    };
    assert_eq!(available_at, until);
    records.push(scenario_event(
        "credential_pool_exhausted",
        "verify",
        "pass",
        json!({
            "provider": key.provider.as_str(),
            "zone_id": key.zone_id.as_str(),
            "behavior": "wait",
            "available_at_unix": available_at.timestamp(),
            "credential_count": 3
        }),
    ));
}

fn append_audit_receipts(registry: &CredentialPoolRegistry, records: &mut Vec<Value>) {
    for audit in registry.audit_events() {
        let audit_value = serde_json::to_value(audit).expect("audit event should serialize");
        records.push(scenario_event(
            "audit_receipt",
            "verify",
            "pass",
            json!({
                "receipt_id": audit_receipt_id(&audit_value),
                "kind": "credential_pool.admin_mutation",
                "op": audit_operation_label(audit.operation),
                "provider": audit.pool_key.provider.as_str(),
                "zone_id": audit.pool_key.zone_id.as_str(),
                "credential_id": audit.credential_id.map(|id| id.to_string()),
                "outcome": audit.outcome.map(mutation_outcome_label)
            }),
        ));
    }
}

fn advance_round_robin_cursor(
    registry: &mut CredentialPoolRegistry,
    key: &CredentialPoolKey,
    acquisitions: usize,
) {
    for _ in 0..acquisitions {
        let lease = registry
            .acquire(key, Utc::now())
            .expect("cursor advance lease should acquire");
        registry
            .release(key, lease.token)
            .expect("cursor advance lease should release");
    }
}

fn acquire_three_after(
    registry: &mut CredentialPoolRegistry,
    key: &CredentialPoolKey,
    now: chrono::DateTime<Utc>,
) -> Vec<CredentialId> {
    let mut ids = Vec::new();
    for _ in 0..3 {
        let lease = registry
            .acquire(key, now)
            .expect("post-cooldown lease should acquire");
        ids.push(lease.credential_id);
        registry
            .release(key, lease.token)
            .expect("post-cooldown lease should release");
    }
    ids
}

fn cooldown_until_for(
    registry: &CredentialPoolRegistry,
    key: &CredentialPoolKey,
    credential_id: CredentialId,
    now: chrono::DateTime<Utc>,
) -> chrono::DateTime<Utc> {
    let view = registry
        .redacted_view(key, now)
        .expect("redacted view should exist");
    let cooldown = view
        .entries
        .iter()
        .find(|entry| entry.credential_id == credential_id)
        .and_then(|entry| entry.cooldown.clone())
        .expect("cooldown should be set");
    let cooldown_is_time_bound = matches!(&cooldown, CredentialCooldown::Until { .. });
    match cooldown {
        CredentialCooldown::Until { until } => until,
        CredentialCooldown::Permanent => {
            assert!(
                cooldown_is_time_bound,
                "rate-limit cooldown should be time-bound"
            );
            now
        }
    }
}

fn registry_with_three_groq_credentials(key: &CredentialPoolKey) -> CredentialPoolRegistry {
    let mut registry = CredentialPoolRegistry::new();
    for (index, material) in [
        (1_u8, MATERIAL_ALPHA),
        (2_u8, MATERIAL_BETA),
        (3_u8, MATERIAL_GAMMA),
    ] {
        registry
            .add_credential(
                key.clone(),
                CredentialPoolStrategy::RoundRobin,
                PooledCredential::new(
                    credential_id(index),
                    CredentialSource::Manual,
                    u32::from(index),
                    format!("groq-key-{index}"),
                    json!({ "material": material }),
                ),
                CredentialUpsertMode::RejectExisting,
            )
            .expect("credential should insert");
    }
    registry
}

fn pool_key() -> CredentialPoolKey {
    CredentialPoolKey::new(
        ProviderKey::new("groq").expect("provider key should validate"),
        ZoneId::work(),
    )
}

fn credential_id(index: u8) -> CredentialId {
    let raw = match index {
        1 => "11111111-1111-1111-1111-111111111111",
        2 => "22222222-2222-2222-2222-222222222222",
        3 => "33333333-3333-3333-3333-333333333333",
        _ => {
            assert!(
                (1..=3).contains(&index),
                "unsupported test credential index {index}"
            );
            "00000000-0000-0000-0000-000000000000"
        }
    };
    CredentialId::parse(raw).expect("static credential id should parse")
}

fn lease_event(
    event: &str,
    phase: &str,
    result: &str,
    key: &CredentialPoolKey,
    credential_id: CredentialId,
    details: Value,
) -> Value {
    scenario_event(
        event,
        phase,
        result,
        json!({
            "provider": key.provider.as_str(),
            "zone_id": key.zone_id.as_str(),
            "credential_id": credential_id.to_string(),
            "source_label": "manual",
            "details": details
        }),
    )
}

fn scenario_event(event: &str, phase: &str, result: &str, details: Value) -> Value {
    json!({
        "schema": SCHEMA,
        "event": event,
        "timestamp": Utc::now().to_rfc3339(),
        "bead": "flywheel_connectors-4kw5f.7.9",
        "phase": phase,
        "result": result,
        "command_line": "cargo test -p fcp-e2e --no-default-features --test credential_pool_e2e -- --nocapture",
        "git_revision": git_revision(),
        "details": details
    })
}

fn live_boundary_skip_record() -> Value {
    let enabled = std::env::var("FCP_E2E_LIVE_CREDENTIAL_POOL_GROQ")
        .ok()
        .is_some_and(|value| !value.trim().is_empty());
    scenario_event(
        "live_boundary_status",
        "verify",
        if enabled { "degraded" } else { "skip" },
        json!({
            "live_fcp_host_spawned": false,
            "live_groq_connector_spawned": false,
            "skip_reason": if enabled {
                "live_boundary_runner_not_wired"
            } else {
                "live_boundary_not_enabled_in_deterministic_ci"
            },
            "required_env": "FCP_E2E_LIVE_CREDENTIAL_POOL_GROQ"
        }),
    )
}

fn audit_operation_label(operation: CredentialPoolAuditOperation) -> &'static str {
    match operation {
        CredentialPoolAuditOperation::CredentialUpsert => "credential_upsert",
        CredentialPoolAuditOperation::CredentialRemove => "credential_remove",
        CredentialPoolAuditOperation::StrategySet => "strategy_set",
        CredentialPoolAuditOperation::MaxConcurrentSet => "max_concurrent_set",
        CredentialPoolAuditOperation::ExhaustedBehaviorSet => "exhausted_behavior_set",
        CredentialPoolAuditOperation::CooldownSet => "cooldown_set",
    }
}

fn mutation_outcome_label(outcome: CredentialMutationOutcome) -> &'static str {
    match outcome {
        CredentialMutationOutcome::Added => "added",
        CredentialMutationOutcome::Replaced => "replaced",
        CredentialMutationOutcome::Removed => "removed",
    }
}

fn audit_receipt_id(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).expect("audit receipt input should serialize");
    format!("blake3:{}", blake3::hash(&bytes).to_hex())
}

fn git_revision() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|revision| revision.trim().to_string())
        .filter(|revision| !revision.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn write_jsonl_artifact(records: &[Value]) -> String {
    let jsonl = records
        .iter()
        .map(|record| serde_json::to_string(record).expect("evidence record should serialize"))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::create_dir_all("target/fcp-credential-pool")
        .expect("artifact directory should be writable");
    let mut file = std::fs::File::create(ARTIFACT_PATH).expect("artifact should be writable");
    file.write_all(jsonl.as_bytes())
        .expect("artifact should write");
    file.write_all(b"\n")
        .expect("artifact newline should write");
    jsonl
}

fn assert_required_events_present(jsonl: &str) {
    for event in [
        "credential_lease_acquired",
        "credential_lease_released",
        "credential_cooldown_set",
        "credential_pool_exhausted",
        "audit_receipt",
        "live_boundary_status",
    ] {
        assert!(jsonl.contains(event), "missing required event {event}");
    }
}

fn assert_redaction_invariants(jsonl: &str) {
    for forbidden in [
        MATERIAL_ALPHA,
        MATERIAL_BETA,
        MATERIAL_GAMMA,
        "Bearer ",
        "api_key",
        "provider error body",
        "private prompt",
    ] {
        assert!(
            !jsonl.contains(forbidden),
            "credential-pool evidence leaked forbidden payload fragment {forbidden:?}"
        );
    }
}
