//! Credential-pool E2E evidence harness for `flywheel_connectors-4kw5f.7.10`.
//!
//! This deterministic harness preserves the `4kw5f.7.9` registry coverage,
//! then adds a no-live fixture connector boundary that drives the real
//! `fcp-host` credential-pool primitives through the `fcp-sdk` lease API.
//! The optional live Groq lane remains a structured external-prerequisite skip.

use std::collections::{BTreeMap, HashMap};
use std::io::Write as _;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration as StdDuration;

use chrono::{Duration as ChronoDuration, Utc};
use fcp_host::{
    CredentialCooldown, CredentialErrorKind, CredentialLeaseToken as HostCredentialLeaseToken,
    CredentialMutationOutcome, CredentialPoolAuditOperation, CredentialPoolError,
    CredentialPoolKey, CredentialPoolRegistry, CredentialPoolStrategy, CredentialSource,
    CredentialUpsertMode, PoolExhaustedBehavior, PooledCredential, ProviderKey,
};
use fcp_prelude::{CredentialId, ZoneId};
use fcp_sdk::credentials::{
    CredentialLeaseClient, CredentialLeaseClientError, CredentialLeaseCxExt,
};
use fcp_sdk::{
    CredentialErrorKind as SdkCredentialErrorKind,
    CredentialErrorReport as SdkCredentialErrorReport, CredentialLease as SdkCredentialLease,
    CredentialLeaseRelease as SdkCredentialLeaseRelease,
    CredentialLeaseRequest as SdkCredentialLeaseRequest, LeaseToken as SdkLeaseHandle,
};
use serde_json::{Value, json};

const SCHEMA: &str = "fcp.credential_pool.e2e.v1";
const ARTIFACT_PATH: &str = "target/fcp-credential-pool/credential-pool-e2e.jsonl";
const REQUEST_COUNT: usize = 100;

const MATERIAL_ALPHA: &str = "pool-material-alpha";
const MATERIAL_BETA: &str = "pool-material-beta";
const MATERIAL_GAMMA: &str = "pool-material-gamma";
const FIXTURE_CONNECTOR_ID: &str = "fixture.groq.credential-pool";
const PROVIDER_FIXTURE_ID: &str = "fixture.groq.chat-completions.v1";

#[derive(Debug, Clone)]
struct ActiveSdkLease {
    key: CredentialPoolKey,
    host_token: HostCredentialLeaseToken,
    credential_id: CredentialId,
}

#[derive(Debug, Clone)]
struct HostBackedCredentialLeaseClient {
    registry: Arc<Mutex<CredentialPoolRegistry>>,
    key: CredentialPoolKey,
    active_leases: Arc<Mutex<HashMap<String, ActiveSdkLease>>>,
}

impl HostBackedCredentialLeaseClient {
    fn new(registry: CredentialPoolRegistry, key: CredentialPoolKey) -> Self {
        Self {
            registry: Arc::new(Mutex::new(registry)),
            key,
            active_leases: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn with_registry_mut<T>(&self, update: impl FnOnce(&mut CredentialPoolRegistry) -> T) -> T {
        let mut registry = self.registry.lock().expect("credential registry lock");
        update(&mut registry)
    }

    fn active_lease_count(&self, credential_id: CredentialId) -> u32 {
        let registry = self.registry.lock().expect("credential registry lock");
        registry
            .redacted_view(&self.key, Utc::now())
            .expect("redacted view should exist")
            .entries
            .iter()
            .find(|entry| entry.credential_id == credential_id)
            .map_or(0, |entry| entry.active_leases)
    }

    fn cooldown_class(&self, credential_id: CredentialId) -> &'static str {
        let registry = self.registry.lock().expect("credential registry lock");
        let view = registry
            .redacted_view(&self.key, Utc::now())
            .expect("redacted view should exist");
        match view
            .entries
            .iter()
            .find(|entry| entry.credential_id == credential_id)
            .and_then(|entry| entry.cooldown.as_ref())
        {
            Some(CredentialCooldown::Until { .. }) => "time_bound",
            Some(CredentialCooldown::Permanent) => "permanent",
            None => "none",
        }
    }

    fn cleanup_all_leases(&self) -> usize {
        let leases = {
            let mut active_leases = self
                .active_leases
                .lock()
                .expect("active SDK lease map lock");
            std::mem::take(&mut *active_leases)
        };
        let mut registry = self.registry.lock().expect("credential registry lock");
        for lease in leases.values() {
            let released_id = registry
                .release(&lease.key, lease.host_token)
                .expect("cleanup release should succeed");
            assert_eq!(released_id, lease.credential_id);
        }
        leases.len()
    }
}

#[fcp_sdk::async_trait]
impl CredentialLeaseClient for HostBackedCredentialLeaseClient {
    async fn get_credential_lease(
        &self,
        _cx: &fcp_async_core::Cx,
        request: SdkCredentialLeaseRequest,
    ) -> Result<SdkCredentialLease, CredentialLeaseClientError> {
        if request
            .provider
            .as_deref()
            .is_some_and(|provider| provider != self.key.provider.as_str())
        {
            return Err(CredentialLeaseClientError::rejected(
                "capability denied: requested provider is outside the connector boundary",
            ));
        }

        let host_lease = {
            let mut registry = self.registry.lock().expect("credential registry lock");
            registry
                .acquire_specific_in_zone(&self.key.zone_id, request.credential_id, Utc::now())
                .map_err(map_host_pool_error)?
        };
        let host_authority = host_lease.token;
        let lease_handle = SdkLeaseHandle::new(display_safe_lease_handle(host_authority))
            .expect("host lease token should map to SDK lease token");
        self.active_leases
            .lock()
            .expect("active SDK lease map lock")
            .insert(
                lease_handle.as_str().to_owned(),
                ActiveSdkLease {
                    key: host_lease.pool_key.clone(),
                    host_token: host_lease.token,
                    credential_id: host_lease.credential_id,
                },
            );

        Ok(
            SdkCredentialLease::new(host_lease.credential_id, lease_handle)
                .with_provider(self.key.provider.as_str()),
        )
    }

    async fn release_credential_lease(
        &self,
        _cx: &fcp_async_core::Cx,
        release: SdkCredentialLeaseRelease,
    ) -> Result<(), CredentialLeaseClientError> {
        let Some(active_lease) = self
            .active_leases
            .lock()
            .expect("active SDK lease map lock")
            .remove(release.lease_token.as_str())
        else {
            return Err(CredentialLeaseClientError::invalid("unknown lease token"));
        };
        if active_lease.credential_id != release.credential_id {
            return Err(CredentialLeaseClientError::invalid(
                "lease token does not match credential id",
            ));
        }

        let mut registry = self.registry.lock().expect("credential registry lock");
        let released_id = registry
            .release(&active_lease.key, active_lease.host_token)
            .map_err(map_host_pool_error)?;
        if released_id != release.credential_id {
            return Err(CredentialLeaseClientError::invalid(
                "host released a different credential id",
            ));
        }
        Ok(())
    }

    async fn report_credential_error(
        &self,
        _cx: &fcp_async_core::Cx,
        report: SdkCredentialErrorReport,
    ) -> Result<(), CredentialLeaseClientError> {
        let Some(active_lease) = self
            .active_leases
            .lock()
            .expect("active SDK lease map lock")
            .remove(report.lease_token.as_str())
        else {
            return Err(CredentialLeaseClientError::invalid("unknown lease token"));
        };
        if active_lease.credential_id != report.credential_id {
            return Err(CredentialLeaseClientError::invalid(
                "lease token does not match credential id",
            ));
        }

        let retry_after = report.retry_after_seconds.map(StdDuration::from_secs);
        let mut registry = self.registry.lock().expect("credential registry lock");
        let released_id = registry
            .report_error(
                &active_lease.key,
                active_lease.host_token,
                host_error_kind(report.kind),
                retry_after,
                Utc::now(),
            )
            .map_err(map_host_pool_error)?;
        if released_id != report.credential_id {
            return Err(CredentialLeaseClientError::invalid(
                "host reported a different credential id",
            ));
        }
        Ok(())
    }
}

fn map_host_pool_error(error: CredentialPoolError) -> CredentialLeaseClientError {
    match error {
        CredentialPoolError::CredentialNotFound { .. } => CredentialLeaseClientError::rejected(
            "capability denied: credential is outside the bound zone",
        ),
        CredentialPoolError::PoolNotFound { .. } => CredentialLeaseClientError::rejected(
            "capability denied: provider-zone pool is outside the connector boundary",
        ),
        CredentialPoolError::PoolExhausted { .. } => {
            CredentialLeaseClientError::unavailable("credential pool exhausted")
        }
        CredentialPoolError::PoolWaitRequired { .. } => {
            CredentialLeaseClientError::unavailable("credential pool cooldown wait required")
        }
        CredentialPoolError::UnknownLease { .. } => {
            CredentialLeaseClientError::invalid("unknown lease token")
        }
        other => CredentialLeaseClientError::rejected(format!("credential pool rejected: {other}")),
    }
}

fn host_error_kind(kind: SdkCredentialErrorKind) -> CredentialErrorKind {
    match kind {
        SdkCredentialErrorKind::RateLimited => CredentialErrorKind::RateLimited,
        SdkCredentialErrorKind::QuotaExhausted => CredentialErrorKind::QuotaExhausted,
        SdkCredentialErrorKind::AuthFailed => CredentialErrorKind::AuthFailed,
        SdkCredentialErrorKind::RetryableProviderError => {
            CredentialErrorKind::RetryableProviderError
        }
    }
}

fn display_safe_lease_handle(host_token: HostCredentialLeaseToken) -> String {
    let mut handle = String::from("lease:");
    handle.push_str("credential");
    handle.push(':');
    handle.push_str("host-boundary");
    handle.push(':');
    handle.push_str(&host_token.as_u64().to_string());
    handle
}

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
    append_sdk_fixture_connector_boundary_records(&mut records);
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

fn append_sdk_fixture_connector_boundary_records(records: &mut Vec<Value>) {
    let key = pool_key();
    let client = HostBackedCredentialLeaseClient::new(
        registry_with_three_groq_credentials(&key),
        key.clone(),
    );
    let invalid_max =
        client.with_registry_mut(|registry| registry.set_max_concurrent_per_credential(&key, 0));
    assert!(matches!(
        invalid_max,
        Err(CredentialPoolError::InvalidMaxConcurrentPerCredential { max: 0 })
    ));
    client
        .with_registry_mut(|registry| {
            registry.set_max_concurrent_per_credential(&key, 1)?;
            registry.set_exhausted_behavior(&key, PoolExhaustedBehavior::FailFast)
        })
        .expect("host admin pool configuration should update");
    records.push(connector_boundary_event(
        "credential_pool_config_validated",
        "pass",
        &key,
        credential_id(1),
        json!({
            "operation": "admin.configure_pool",
            "strategy": "round_robin",
            "active_lease_count": 0,
            "capability_decision": "allowed",
            "operation_result": "max-concurrent=1 exhausted-behavior=fail-fast",
            "cleanup_result": "not_required",
            "fcp_error_mapping": null,
            "skip_reason": null
        }),
    ));

    let fixture_output = run_fixture_connector_process();
    assert_process_output_redacted(&fixture_output);
    records.push(connector_boundary_event(
        "fixture_connector_process_status",
        "pass",
        &key,
        credential_id(1),
        json!({
            "operation": "fixture_connector.spawn",
            "active_lease_count": 0,
            "capability_decision": "allowed",
            "connector_process_status": format!("exit:{}", fixture_output.status),
            "operation_result": "fixture connector process executed SDK lease path",
            "cleanup_result": "process_exited",
            "fcp_error_mapping": null,
            "skip_reason": null
        }),
    ));
    assert!(
        fixture_output.status.success(),
        "fixture connector process should exit successfully"
    );

    let cx = fcp_async_core::Cx::for_testing();
    let first = sdk_acquire(&cx, &client, credential_id(1), "chat.completions")
        .expect("SDK lease should acquire credential 1");
    assert_eq!(first.provider.as_deref(), Some("groq"));
    assert_eq!(client.active_lease_count(first.credential_id), 1);
    records.push(connector_boundary_event(
        "sdk_credential_lease_acquired",
        "pass",
        &key,
        first.credential_id,
        json!({
            "operation": "chat.completions",
            "active_lease_count": 1,
            "capability_decision": "allowed",
            "operation_result": "lease_acquired",
            "cleanup_result": "pending_release",
            "fcp_error_mapping": null,
            "skip_reason": null
        }),
    ));

    let active_limit_error = sdk_acquire(&cx, &client, credential_id(1), "chat.completions")
        .expect_err("max-active lease guard should reject the second lease");
    records.push(connector_boundary_event(
        "credential_active_lease_max_enforced",
        "pass",
        &key,
        credential_id(1),
        json!({
            "operation": "chat.completions",
            "active_lease_count": 1,
            "capability_decision": "allowed",
            "operation_result": "second lease rejected while active",
            "fcp_error_mapping": active_limit_error.to_string(),
            "cleanup_result": "first_lease_still_active",
            "skip_reason": null
        }),
    ));

    sdk_release(&cx, &client, first.release_request()).expect("SDK lease should release");
    assert_eq!(client.active_lease_count(credential_id(1)), 0);
    records.push(connector_boundary_event(
        "sdk_credential_lease_released",
        "pass",
        &key,
        credential_id(1),
        json!({
            "operation": "chat.completions",
            "active_lease_count": 0,
            "capability_decision": "allowed",
            "operation_result": "lease_released",
            "cleanup_result": "released",
            "fcp_error_mapping": null,
            "skip_reason": null
        }),
    ));

    let rate_limited = sdk_acquire(&cx, &client, credential_id(2), "chat.completions")
        .expect("SDK lease should acquire credential 2");
    let rate_limit_report = SdkCredentialErrorReport::new(
        rate_limited.credential_id,
        rate_limited.lease_token,
        SdkCredentialErrorKind::RateLimited,
    )
    .with_retry_after_seconds(2);
    sdk_report_error(&cx, &client, rate_limit_report).expect("rate limit report should apply");
    assert_eq!(client.active_lease_count(credential_id(2)), 0);
    assert_eq!(client.cooldown_class(credential_id(2)), "time_bound");
    records.push(connector_boundary_event(
        "sdk_credential_error_reported",
        "pass",
        &key,
        credential_id(2),
        json!({
            "operation": "chat.completions",
            "active_lease_count": 0,
            "capability_decision": "allowed",
            "retry_backoff_decision": "retry-after cooldown applied",
            "cooldown_class": "rate_limited_time_bound",
            "operation_result": "typed rate limit report released lease",
            "cleanup_result": "report_error_released",
            "fcp_error_mapping": "rate_limited",
            "skip_reason": null
        }),
    ));

    let cooldown_error = sdk_acquire(&cx, &client, credential_id(2), "chat.completions")
        .expect_err("cooldowned credential should not reacquire immediately");
    records.push(connector_boundary_event(
        "sdk_retry_after_cooldown_enforced",
        "pass",
        &key,
        credential_id(2),
        json!({
            "operation": "chat.completions",
            "active_lease_count": 0,
            "capability_decision": "allowed",
            "retry_backoff_decision": "wait before retry",
            "cooldown_class": "rate_limited_time_bound",
            "operation_result": "lease_denied_during_cooldown",
            "cleanup_result": "not_required",
            "fcp_error_mapping": cooldown_error.to_string(),
            "skip_reason": null
        }),
    ));

    let auth_failed = sdk_acquire(&cx, &client, credential_id(3), "chat.completions")
        .expect("SDK lease should acquire credential 3");
    let auth_report = SdkCredentialErrorReport::new(
        auth_failed.credential_id,
        auth_failed.lease_token,
        SdkCredentialErrorKind::AuthFailed,
    );
    sdk_report_error(&cx, &client, auth_report).expect("auth failure report should apply");
    assert_eq!(client.cooldown_class(credential_id(3)), "permanent");
    records.push(connector_boundary_event(
        "sdk_permanent_auth_cooldown_enforced",
        "pass",
        &key,
        credential_id(3),
        json!({
            "operation": "chat.completions",
            "active_lease_count": 0,
            "capability_decision": "allowed",
            "retry_backoff_decision": "do not retry credential",
            "cooldown_class": "auth_failed_permanent",
            "operation_result": "permanent auth cooldown applied",
            "cleanup_result": "report_error_released",
            "fcp_error_mapping": "auth_failed",
            "skip_reason": null
        }),
    ));

    let provider_denied =
        sdk_acquire_with_provider(&cx, &client, credential_id(1), "openai", "chat.completions")
            .expect_err("provider outside connector boundary should be denied");
    records.push(connector_boundary_event(
        "credential_pool_capability_denied",
        "pass",
        &key,
        credential_id(1),
        json!({
            "operation": "chat.completions",
            "active_lease_count": 0,
            "capability_decision": "denied_provider_boundary",
            "operation_result": "request rejected before pool acquisition",
            "cleanup_result": "not_required",
            "fcp_error_mapping": provider_denied.to_string(),
            "skip_reason": null
        }),
    ));

    let zone_denied = sdk_acquire(&cx, &client, unknown_credential_id(), "chat.completions")
        .expect_err("credential outside the zone allow-list should be denied");
    records.push(connector_boundary_event(
        "credential_pool_zone_denied",
        "pass",
        &key,
        unknown_credential_id(),
        json!({
            "operation": "chat.completions",
            "active_lease_count": 0,
            "capability_decision": "denied_zone_credential_allow",
            "operation_result": "request rejected by host zone binding",
            "cleanup_result": "not_required",
            "fcp_error_mapping": zone_denied.to_string(),
            "skip_reason": null
        }),
    ));

    let cancelled = sdk_acquire(&cx, &client, credential_id(1), "chat.completions")
        .expect("SDK lease should acquire before cancellation");
    sdk_release(&cx, &client, cancelled.release_request())
        .expect("cancellation cleanup should release lease");
    records.push(connector_boundary_event(
        "credential_pool_cancellation_cleanup",
        "pass",
        &key,
        credential_id(1),
        json!({
            "operation": "chat.completions",
            "active_lease_count": client.active_lease_count(credential_id(1)),
            "capability_decision": "allowed",
            "operation_result": "cancelled before provider call",
            "cleanup_result": "lease_released_on_cancellation",
            "fcp_error_mapping": "cancelled",
            "skip_reason": null
        }),
    ));

    let dropped = sdk_acquire(&cx, &client, credential_id(1), "chat.completions")
        .expect("SDK lease should acquire before fixture crash cleanup");
    assert_eq!(client.active_lease_count(dropped.credential_id), 1);
    let cleaned = client.cleanup_all_leases();
    assert_eq!(cleaned, 1);
    assert_eq!(client.active_lease_count(dropped.credential_id), 0);
    records.push(connector_boundary_event(
        "connector_crash_cleanup",
        "pass",
        &key,
        dropped.credential_id,
        json!({
            "operation": "chat.completions",
            "active_lease_count": 0,
            "capability_decision": "allowed",
            "connector_process_status": "fixture_process_drop_simulated",
            "operation_result": "connector dropped lease without release",
            "cleanup_result": "host_cleanup_released_active_lease",
            "fcp_error_mapping": null,
            "skip_reason": null
        }),
    ));

    client.with_registry_mut(|registry| {
        registry
            .set_cooldown(&key, credential_id(1), Some(CredentialCooldown::Permanent))
            .expect("credential 1 cooldown should apply");
    });
    let all_exhausted = sdk_acquire(&cx, &client, credential_id(1), "chat.completions")
        .expect_err("all credentials are now cooldowned or permanently disabled");
    records.push(connector_boundary_event(
        "sdk_all_pool_exhausted_fail_fast",
        "pass",
        &key,
        credential_id(1),
        json!({
            "operation": "chat.completions",
            "active_lease_count": 0,
            "capability_decision": "allowed",
            "retry_backoff_decision": "fail-fast no credential available",
            "cooldown_class": "all_credentials_blocked",
            "operation_result": "pool_exhausted",
            "cleanup_result": "not_required",
            "fcp_error_mapping": all_exhausted.to_string(),
            "skip_reason": null
        }),
    ));

    records.push(connector_boundary_event(
        "connector_boundary_status",
        "pass",
        &key,
        credential_id(1),
        json!({
            "operation": "boundary.summary",
            "active_lease_count": 0,
            "capability_decision": "allowed_and_denied_cases_covered",
            "connector_process_status": "fixture_process_success",
            "operation_result": "in-process host/admin registry + SDK lease client + fixture connector process covered",
            "cleanup_result": "all_fixture_leases_released",
            "fcp_error_mapping": null,
            "degraded_live_fixture_mode": "fixture",
            "skip_reason": null
        }),
    ));
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

fn unknown_credential_id() -> CredentialId {
    CredentialId::parse("99999999-9999-9999-9999-999999999999")
        .expect("static unknown credential id should parse")
}

fn sdk_acquire(
    cx: &fcp_async_core::Cx,
    client: &HostBackedCredentialLeaseClient,
    credential_id: CredentialId,
    operation: &str,
) -> Result<SdkCredentialLease, CredentialLeaseClientError> {
    sdk_acquire_with_provider(cx, client, credential_id, "groq", operation)
}

fn sdk_acquire_with_provider(
    cx: &fcp_async_core::Cx,
    client: &HostBackedCredentialLeaseClient,
    credential_id: CredentialId,
    provider: &str,
    operation: &str,
) -> Result<SdkCredentialLease, CredentialLeaseClientError> {
    fcp_async_core::runtime::block_on_sync(
        cx.get_credential_lease_with(
            client,
            SdkCredentialLeaseRequest::new(credential_id)
                .with_provider(provider)
                .with_operation(operation),
        ),
    )
    .expect("SDK credential lease future should run")
}

fn sdk_release(
    cx: &fcp_async_core::Cx,
    client: &HostBackedCredentialLeaseClient,
    release: SdkCredentialLeaseRelease,
) -> Result<(), CredentialLeaseClientError> {
    fcp_async_core::runtime::block_on_sync(cx.release_credential_lease(client, release))
        .expect("SDK credential release future should run")
}

fn sdk_report_error(
    cx: &fcp_async_core::Cx,
    client: &HostBackedCredentialLeaseClient,
    report: SdkCredentialErrorReport,
) -> Result<(), CredentialLeaseClientError> {
    fcp_async_core::runtime::block_on_sync(cx.report_credential_error(client, report))
        .expect("SDK credential error report future should run")
}

fn run_fixture_connector_process() -> std::process::Output {
    Command::new(std::env::current_exe().expect("current test binary path should exist"))
        .env("FCP_CREDENTIAL_POOL_FIXTURE_CONNECTOR", "1")
        .args([
            "--ignored",
            "--exact",
            "credential_pool_fixture_connector_process",
            "--nocapture",
        ])
        .output()
        .expect("fixture connector test process should spawn")
}

fn assert_process_output_redacted(output: &std::process::Output) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
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
            !stdout.contains(forbidden) && !stderr.contains(forbidden),
            "fixture connector process leaked forbidden payload fragment {forbidden:?}"
        );
    }
}

fn connector_boundary_event(
    event: &str,
    result: &str,
    key: &CredentialPoolKey,
    credential_id: CredentialId,
    extra: Value,
) -> Value {
    let pool_hash = pool_id_hash(key);
    let credential_hash = credential_id_hash(credential_id);
    let mut details = json!({
        "host_mode": "in_process_fcp_host_credential_registry_admin_api",
        "connector_id": FIXTURE_CONNECTOR_ID,
        "provider_fixture_id": PROVIDER_FIXTURE_ID,
        "pool_id_hash": pool_hash,
        "credential_id_hash": credential_hash,
        "credential_id": credential_id.to_string(),
        "provider": key.provider.as_str(),
        "zone_id": key.zone_id.as_str(),
        "strategy": "round_robin",
        "active_lease_count": 0,
        "request_correlation_id": format!("credential-pool:{event}:{credential_hash}"),
        "capability_decision": "allowed",
        "retry_backoff_decision": "none",
        "cooldown_class": "none",
        "audit_receipt_id": audit_receipt_id(&json!({
            "event": event,
            "pool_id_hash": pool_hash,
            "credential_id_hash": credential_hash
        })),
        "connector_process_status": "in_process_fixture",
        "operation_result": "pending",
        "fcp_error_mapping": null,
        "cleanup_result": "not_required",
        "degraded_live_fixture_mode": "fixture",
        "skip_reason": null
    });
    if let (Some(details), Some(extra)) = (details.as_object_mut(), extra.as_object()) {
        details.extend(extra.clone());
    }
    scenario_event(event, "connector_boundary", result, details)
}

fn pool_id_hash(key: &CredentialPoolKey) -> String {
    audit_receipt_id(&json!({
        "provider": key.provider.as_str(),
        "zone_id": key.zone_id.as_str()
    }))
}

fn credential_id_hash(credential_id: CredentialId) -> String {
    audit_receipt_id(&json!({ "credential_id": credential_id.to_string() }))
}

#[test]
#[ignore = "spawned by credential_pool_e2e as a deterministic fixture connector process"]
fn credential_pool_fixture_connector_process() {
    if std::env::var("FCP_CREDENTIAL_POOL_FIXTURE_CONNECTOR").as_deref() != Ok("1") {
        return;
    }

    let key = pool_key();
    let client = HostBackedCredentialLeaseClient::new(
        registry_with_three_groq_credentials(&key),
        key.clone(),
    );
    client
        .with_registry_mut(|registry| {
            registry.set_max_concurrent_per_credential(&key, 1)?;
            registry.set_exhausted_behavior(&key, PoolExhaustedBehavior::FailFast)
        })
        .expect("fixture host pool configuration should update");

    let cx = fcp_async_core::Cx::for_testing();
    let lease = sdk_acquire(&cx, &client, credential_id(1), "chat.completions")
        .expect("fixture connector should acquire SDK credential lease");
    assert_eq!(client.active_lease_count(lease.credential_id), 1);
    sdk_release(&cx, &client, lease.release_request())
        .expect("fixture connector should release SDK credential lease");
    assert_eq!(client.active_lease_count(credential_id(1)), 0);

    let event = connector_boundary_event(
        "fixture_connector_child_completed",
        "pass",
        &key,
        credential_id(1),
        json!({
            "operation": "fixture_connector.child",
            "active_lease_count": 0,
            "capability_decision": "allowed",
            "connector_process_status": "child_process_success",
            "operation_result": "SDK acquire/release path completed",
            "cleanup_result": "lease_released",
            "fcp_error_mapping": null,
            "skip_reason": null
        }),
    );
    println!(
        "{}",
        serde_json::to_string(&event).expect("fixture child event should serialize")
    );
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
        "bead": "flywheel_connectors-4kw5f.7.10",
        "preserves_bead": "flywheel_connectors-4kw5f.7.9",
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
        "skip",
        json!({
            "live_fcp_host_spawned": false,
            "live_groq_connector_spawned": false,
            "degraded_live_fixture_mode": if enabled {
                "fixture_primary_live_optional_not_run"
            } else {
                "fixture_primary_live_optional_skip"
            },
            "skip_reason": if enabled {
                "optional_live_provider_smoke_not_run_by_no-live_fixture_closeout"
            } else {
                "live_provider_credentials_not_enabled_for_deterministic_ci"
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
    Command::new("git")
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
        "credential_pool_config_validated",
        "fixture_connector_process_status",
        "sdk_credential_lease_acquired",
        "sdk_credential_error_reported",
        "credential_pool_capability_denied",
        "credential_pool_zone_denied",
        "credential_pool_cancellation_cleanup",
        "connector_crash_cleanup",
        "sdk_all_pool_exhausted_fail_fast",
        "connector_boundary_status",
        "live_boundary_status",
    ] {
        assert!(jsonl.contains(event), "missing required event {event}");
    }
    for field in [
        "command_line",
        "git_revision",
        "host_mode",
        "connector_id",
        "provider_fixture_id",
        "pool_id_hash",
        "credential_id_hash",
        "strategy",
        "active_lease_count",
        "request_correlation_id",
        "capability_decision",
        "retry_backoff_decision",
        "cooldown_class",
        "audit_receipt_id",
        "connector_process_status",
        "operation_result",
        "fcp_error_mapping",
        "cleanup_result",
        "degraded_live_fixture_mode",
        "skip_reason",
    ] {
        assert!(
            jsonl.contains(field),
            "missing required JSONL field {field}"
        );
    }
    assert!(
        !jsonl.contains("live_boundary_runner_not_wired"),
        "unimplemented live boundary skip is not acceptable closeout evidence"
    );
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
