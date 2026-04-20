#![no_main]

mod audit_tamper_chain_events;

use arbitrary::{Arbitrary, Unstructured};
use fcp_audit::{
    AuditEntry, ChainHead, Severity, TraceContext, VerifyIssue, VerifyStatus, verify_chain,
};
use libfuzzer_sys::fuzz_target;
use serde::Deserialize;
use std::collections::BTreeMap;

const MAX_ENTRIES: usize = 16;
const MAX_TEXT_LEN: usize = 32;

#[derive(Debug, Clone, Deserialize)]
struct AuditSeed {
    vector_path: Option<String>,
    zone_filter: Option<String>,
    head: Option<AuditHeadSeed>,
    tamper: Option<Vec<AuditTamperSeed>>,
    entries: Option<Vec<AuditEntrySeed>>,
}

#[derive(Debug, Clone, Deserialize)]
struct AuditHeadSeed {
    zone_id: Option<String>,
    head_entry: Option<String>,
    head_seq: Option<u64>,
    coverage: Option<f64>,
    epoch_id: Option<String>,
    signature_count: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
struct AuditEntrySeed {
    id: Option<String>,
    event_type: Option<String>,
    actor: Option<String>,
    zone_id: Option<String>,
    seq: Option<u64>,
    occurred_at: Option<u64>,
    prev: Option<String>,
    correlation_id: Option<String>,
    connector_id: Option<String>,
    operation_id: Option<String>,
    trace_id: Option<String>,
    span_id: Option<String>,
    flags: Option<u8>,
}

#[derive(Debug, Clone, Deserialize)]
struct AuditTamperSeed {
    action: Option<String>,
    index: Option<usize>,
    target: Option<usize>,
    value: Option<String>,
    seq: Option<u64>,
    occurred_at: Option<u64>,
}

fn bounded_len(u: &mut Unstructured<'_>, max_len: usize) -> usize {
    u.int_in_range(0..=max_len).unwrap_or(0)
}

fn bounded_bytes(u: &mut Unstructured<'_>, max_len: usize) -> Vec<u8> {
    let len = bounded_len(u, max_len);
    u.bytes(len).map(ToOwned::to_owned).unwrap_or_default()
}

fn bounded_string(u: &mut Unstructured<'_>, max_len: usize) -> String {
    String::from_utf8_lossy(&bounded_bytes(u, max_len)).into_owned()
}

fn random_event_type(u: &mut Unstructured<'_>) -> String {
    match u.int_in_range(0..=7).unwrap_or(0) {
        0 => "secret.access".to_string(),
        1 => "capability.invoke".to_string(),
        2 => "elevation.granted".to_string(),
        3 => "declassification.granted".to_string(),
        4 => "zone.transition".to_string(),
        5 => "revocation.issued".to_string(),
        6 => "security.violation".to_string(),
        _ => bounded_string(u, MAX_TEXT_LEN),
    }
}

fn optional_string(u: &mut Unstructured<'_>, max_len: usize) -> Option<String> {
    if u.arbitrary::<bool>().unwrap_or(false) {
        Some(bounded_string(u, max_len))
    } else {
        None
    }
}

fn audit_from_unstructured(data: &[u8]) -> AuditSeed {
    let mut u = Unstructured::new(data);
    let entry_count = bounded_len(&mut u, MAX_ENTRIES);
    let mut entries = Vec::with_capacity(entry_count);
    for index in 0..entry_count {
        let seq = u64::arbitrary(&mut u).unwrap_or(index as u64);
        let occurred_at = u64::arbitrary(&mut u).unwrap_or(seq);
        let flags = if u.arbitrary::<bool>().unwrap_or(false) {
            Some(u8::arbitrary(&mut u).unwrap_or(0))
        } else {
            None
        };
        entries.push(AuditEntrySeed {
            id: Some({
                let id = bounded_string(&mut u, MAX_TEXT_LEN);
                if id.is_empty() {
                    format!("entry-{index}")
                } else {
                    id
                }
            }),
            event_type: Some(random_event_type(&mut u)),
            actor: Some({
                let actor = bounded_string(&mut u, MAX_TEXT_LEN);
                if actor.is_empty() {
                    format!("actor-{index}")
                } else {
                    actor
                }
            }),
            zone_id: Some({
                let zone = bounded_string(&mut u, MAX_TEXT_LEN);
                if zone.is_empty() {
                    "z:work".to_string()
                } else {
                    zone
                }
            }),
            seq: Some(seq),
            occurred_at: Some(occurred_at),
            prev: optional_string(&mut u, MAX_TEXT_LEN),
            correlation_id: Some(bounded_string(&mut u, MAX_TEXT_LEN)),
            connector_id: optional_string(&mut u, MAX_TEXT_LEN),
            operation_id: optional_string(&mut u, MAX_TEXT_LEN),
            trace_id: optional_string(&mut u, 32),
            span_id: optional_string(&mut u, 16),
            flags,
        });
    }

    let head = if u.arbitrary::<bool>().unwrap_or(false) {
        Some(AuditHeadSeed {
            zone_id: Some({
                let zone = bounded_string(&mut u, MAX_TEXT_LEN);
                if zone.is_empty() {
                    "z:work".to_string()
                } else {
                    zone
                }
            }),
            head_entry: Some(bounded_string(&mut u, MAX_TEXT_LEN)),
            head_seq: Some(u64::arbitrary(&mut u).unwrap_or(0)),
            coverage: Some(f64::from(u16::arbitrary(&mut u).unwrap_or(0)) / 10_000.0),
            epoch_id: Some(bounded_string(&mut u, MAX_TEXT_LEN)),
            signature_count: Some(u32::from(u16::arbitrary(&mut u).unwrap_or(0))),
        })
    } else {
        None
    };

    AuditSeed {
        vector_path: None,
        zone_filter: optional_string(&mut u, MAX_TEXT_LEN),
        head,
        tamper: None,
        entries: Some(entries),
    }
}

fn audit_input(data: &[u8]) -> AuditSeed {
    serde_json::from_slice::<AuditSeed>(data).unwrap_or_else(|_| audit_from_unstructured(data))
}

fn truncate_utf8(value: &mut String, max_len: usize) {
    if value.len() <= max_len {
        return;
    }
    let mut boundary = max_len;
    while boundary > 0 && !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value.truncate(boundary);
}

fn to_entry(seed: AuditEntrySeed, index: usize) -> AuditEntry {
    let event_type = seed
        .event_type
        .unwrap_or_else(|| "capability.invoke".to_string());
    let trace_context = match (seed.trace_id, seed.span_id) {
        (Some(trace_id), Some(span_id)) => Some(TraceContext {
            trace_id,
            span_id,
            flags: seed.flags.unwrap_or(0),
        }),
        _ => None,
    };

    AuditEntry {
        id: seed.id.unwrap_or_else(|| format!("entry-{index}")),
        event_type: event_type.clone(),
        severity: Severity::for_event_type(&event_type),
        actor: seed.actor.unwrap_or_else(|| format!("actor-{index}")),
        zone_id: seed.zone_id.unwrap_or_else(|| "z:work".to_string()),
        seq: seed.seq.unwrap_or(index as u64),
        occurred_at: seed.occurred_at.unwrap_or(index as u64),
        prev: seed.prev,
        correlation_id: seed.correlation_id.unwrap_or_default(),
        trace_context,
        connector_id: seed.connector_id,
        operation_id: seed.operation_id,
        metadata: BTreeMap::new(),
    }
}

fn to_head(seed: AuditHeadSeed) -> ChainHead {
    ChainHead {
        zone_id: seed.zone_id.unwrap_or_else(|| "z:work".to_string()),
        head_entry: seed.head_entry.unwrap_or_default(),
        head_seq: seed.head_seq.unwrap_or(0),
        coverage: seed.coverage.unwrap_or(0.0).clamp(0.0, 1.0),
        epoch_id: seed.epoch_id.unwrap_or_default(),
        signature_count: seed.signature_count.unwrap_or(0),
    }
}

fn expected_status(issues: &[VerifyIssue]) -> VerifyStatus {
    if issues.is_empty() {
        VerifyStatus::Ok
    } else if issues.iter().any(VerifyIssue::is_critical) {
        VerifyStatus::Fail
    } else {
        VerifyStatus::Warn
    }
}

fuzz_target!(|data: &[u8]| {
    let mut seed = audit_input(data);
    audit_tamper_chain_events::hydrate_from_vector(&mut seed);
    audit_tamper_chain_events::apply_tampering(&mut seed);
    let mut entries = seed
        .entries
        .take()
        .unwrap_or_default()
        .into_iter()
        .take(MAX_ENTRIES)
        .enumerate()
        .map(|(index, entry)| to_entry(entry, index))
        .collect::<Vec<_>>();

    if let Some(first) = entries.first_mut() {
        truncate_utf8(&mut first.id, MAX_TEXT_LEN);
        truncate_utf8(&mut first.actor, MAX_TEXT_LEN);
        truncate_utf8(&mut first.zone_id, MAX_TEXT_LEN);
    }

    let head = seed.head.take().map(to_head);
    let report = verify_chain(&entries, head.as_ref(), seed.zone_filter.as_deref());
    let expected_head_seq = if entries.is_empty() {
        None
    } else {
        head.as_ref().map(|value| value.head_seq)
    };
    let expected_head_entry = if entries.is_empty() {
        None
    } else {
        head.as_ref().map(|value| value.head_entry.as_str())
    };

    assert_eq!(report.chain_len, entries.len());
    assert_eq!(report.zone_id.as_deref(), seed.zone_filter.as_deref());
    assert_eq!(report.head_seq, expected_head_seq);
    assert_eq!(report.head_entry.as_deref(), expected_head_entry);
    assert_eq!(report.is_clean(), report.issues.is_empty());
    assert_eq!(
        report.critical_count(),
        report
            .issues
            .iter()
            .filter(|issue| issue.is_critical())
            .count()
    );
    assert_eq!(report.status, expected_status(&report.issues));
});
