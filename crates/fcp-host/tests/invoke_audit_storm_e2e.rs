//! Redaction-safe same-zone invoke-audit storm evidence for evxvv.5.4.
//!
//! This is an e2e-style harness around the production `InvokeAuditChain`
//! append path. It does not optimize the path; it records the baseline
//! topology, latency samples, retry/fallback counters, and chain-isomorphism
//! proof that the optimization bead requires before any later code change.

use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

use fcp_audit::AuditEntry;
use fcp_host::{InvokeAuditChain, InvokeAuditChainMetrics, InvokeAuditContext, InvokePhase};
use serde_json::{Value, json};

const JSONL_PREFIX: &str = "INVOKE_AUDIT_STORM_JSONL";
const ZONE_ID: &str = "z:evxvv-5-4-storm";

fn ctx(worker: usize, append: usize) -> InvokeAuditContext {
    InvokeAuditContext {
        zone_id: ZONE_ID.into(),
        actor: format!("agent:storm-{worker}"),
        connector_id: "github".into(),
        operation: "list_repos".into(),
        operation_id: format!("worker-{worker}-append-{append}"),
        correlation_id: None,
        occurred_at: 1_700_000_000,
    }
}

fn env_or_unknown(keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| std::env::var(key).ok().filter(|value| !value.is_empty()))
        .unwrap_or_else(|| "unknown".into())
}

fn command_first_line(command: &str) -> Option<String> {
    let output = std::process::Command::new(command).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    let value = stdout.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

fn worker_identity() -> String {
    let value = env_or_unknown(&[
        "FCP_WORKER_ID",
        "RCH_WORKER_ID",
        "RCH_WORKER_NAME",
        "HOSTNAME",
        "COMPUTERNAME",
    ]);
    if value == "unknown" {
        command_first_line("hostname").unwrap_or(value)
    } else {
        value
    }
}

fn command_line() -> String {
    std::env::var("FCP_TEST_COMMAND_LINE").unwrap_or_else(|_| {
        std::env::args()
            .map(|arg| {
                if arg.contains(char::is_whitespace) {
                    format!("{arg:?}")
                } else {
                    arg
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    })
}

fn percentile(sorted: &[u128], permille: u128) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let last = sorted.len() - 1;
    let index = (last as u128 * permille).div_ceil(1000);
    sorted[index as usize]
}

fn verify_chain(entries: &[AuditEntry], expected_len: usize) -> Result<(), String> {
    if entries.len() != expected_len {
        return Err(format!(
            "entry count mismatch: expected {expected_len}, got {}",
            entries.len()
        ));
    }
    let Some(first) = entries.first() else {
        return Err("missing genesis entry".into());
    };
    if !first.is_genesis() {
        return Err("first entry is not genesis".into());
    }
    for (index, entry) in entries.iter().enumerate() {
        if entry.seq != index as u64 {
            return Err(format!(
                "sequence mismatch at index {index}: expected {index}, got {}",
                entry.seq
            ));
        }
        if entry.zone_id != ZONE_ID {
            return Err(format!(
                "zone mismatch at index {index}: expected {ZONE_ID}, got {}",
                entry.zone_id
            ));
        }
        if index > 0 && !entry.follows(&entries[index - 1]) {
            return Err(format!("hash linkage broke at index {index}"));
        }
    }
    let report = fcp_audit::verify_chain(entries, None, Some(ZONE_ID));
    if !report.is_clean() || !report.status.is_ok() {
        return Err(format!("fcp_audit::verify_chain reported {report:?}"));
    }
    Ok(())
}

fn latency_summary(sorted_samples: &[u128]) -> Value {
    json!({
        "sample_count": sorted_samples.len(),
        "p50_nanos": percentile(sorted_samples, 500),
        "p95_nanos": percentile(sorted_samples, 950),
        "p99_nanos": percentile(sorted_samples, 990),
        "p999_nanos": percentile(sorted_samples, 999),
        "max_nanos": sorted_samples.last().copied().unwrap_or(0),
    })
}

fn metrics_json(metrics: InvokeAuditChainMetrics) -> Value {
    json!({
        "entries": metrics.entries,
        "optimistic_commits": metrics.optimistic_commits,
        "stale_head_retries": metrics.stale_head_retries,
        "serialized_fallbacks": metrics.serialized_fallbacks,
        "contention_exhaustions": metrics.contention_exhaustions,
        "committed_entries": metrics.committed_entries(),
    })
}

fn run_same_zone_storm(scenario_id: &str, concurrency: usize, appends_per_worker: usize) -> Value {
    let total_appends = concurrency * appends_per_worker;
    let chain = Arc::new(InvokeAuditChain::new());
    let barrier = Arc::new(Barrier::new(concurrency + 1));
    let mut handles = Vec::with_capacity(concurrency);

    for worker in 0..concurrency {
        let chain = Arc::clone(&chain);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let mut samples = Vec::with_capacity(appends_per_worker);
            barrier.wait();
            for append in 0..appends_per_worker {
                let start = Instant::now();
                chain
                    .append(&ctx(worker, append), InvokePhase::PreflightAllow)
                    .expect("same-zone storm append must not drop audit events");
                samples.push(start.elapsed().as_nanos());
            }
            samples
        }));
    }

    let elapsed_start = Instant::now();
    barrier.wait();
    let mut samples = Vec::with_capacity(total_appends);
    for handle in handles {
        samples.extend(handle.join().expect("storm worker panicked"));
    }
    let elapsed = elapsed_start.elapsed();
    samples.sort_unstable();

    let entries = chain.entries_for_zone(ZONE_ID);
    verify_chain(&entries, total_appends).expect("storm chain isomorphism must hold");
    let metrics = chain.metrics_for_zone(ZONE_ID);
    assert_eq!(metrics.entries, total_appends);
    assert_eq!(metrics.committed_entries(), total_appends);
    assert_eq!(
        metrics.contention_exhaustions, 0,
        "production fallback must prevent audit-loss contention errors"
    );
    if concurrency >= 512 {
        assert!(
            metrics.stale_head_retries > 0 || metrics.serialized_fallbacks > 0,
            "c=512 lane must observe contention counters"
        );
    }

    let include_raw_samples = std::env::var("FCP_INVOKE_AUDIT_STORM_RAW_SAMPLES")
        .is_ok_and(|value| matches!(value.as_str(), "1" | "true" | "yes"));
    let raw_samples = include_raw_samples.then_some(json!(samples));

    let mut record = json!({
        "event": "invoke_audit_same_zone_storm",
        "bead_id": "flywheel_connectors-evxvv.5.4",
        "scenario_id": scenario_id,
        "command_line": command_line(),
        "command_args": std::env::args().collect::<Vec<_>>(),
        "git_revision": env_or_unknown(&["FCP_GIT_REVISION", "VERGEN_GIT_SHA"]),
        "worker_identity": worker_identity(),
        "cargo_target_dir": env_or_unknown(&["CARGO_TARGET_DIR"]),
        "topology": {
            "mode": "same_zone",
            "zone_id": ZONE_ID,
            "concurrency": concurrency,
            "appends_per_worker": appends_per_worker,
            "total_appends": total_appends,
        },
        "latency": latency_summary(&samples),
        "duration_ms": elapsed.as_millis(),
        "metrics": metrics_json(metrics),
        "isomorphism": {
            "entry_count_matches": entries.len() == total_appends,
            "dense_monotonic_seq": true,
            "prev_hash_linkage": true,
            "audit_verify_chain_clean": true,
            "ordering_preserved": "commit-order sequence and previous-id linkage preserved",
        },
        "redaction_decision": "operation ids, zone id, counters, and timings only; no prompts, payloads, credentials, or PII read",
        "cleanup_result": "not_applicable_no_temp_resources",
        "skip_reason": null,
    });
    if let Some(raw_samples) = raw_samples {
        record["raw_samples_nanos"] = raw_samples;
    }
    record
}

#[test]
fn same_zone_audit_storm_e2e_jsonl_covers_c128_and_c512() {
    let records = [
        run_same_zone_storm("same_zone_c128", 128, 16),
        run_same_zone_storm("same_zone_c512", 512, 8),
    ];

    for record in records {
        println!(
            "{JSONL_PREFIX} {}",
            serde_json::to_string(&record).expect("storm evidence JSONL must serialize")
        );
    }
}
