use super::{AuditEntrySeed, AuditHeadSeed, AuditSeed};
use serde::Deserialize;
use std::fs;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
struct CoreAuditChainVector {
    description: String,
    events: Vec<CoreAuditEventVector>,
    chain_length: usize,
    head_seq: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct CoreAuditEventVector {
    description: String,
    event_type: String,
    seq: u64,
    prev_hex: Option<String>,
    zone_id: String,
    actor: String,
    occurred_at: u64,
}

fn audit_vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../crates/fcp-core/tests/vectors")
}

fn safe_vector_path(root: &Path, name: &str) -> Option<PathBuf> {
    let path = Path::new(name);
    if path.is_absolute() {
        return None;
    }
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return None;
    }
    Some(root.join(path))
}

fn load_audit_vector(name: &str) -> Option<CoreAuditChainVector> {
    let path = safe_vector_path(&audit_vectors_dir(), name)?;
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub(crate) fn hydrate_from_vector(seed: &mut AuditSeed) {
    let Some(vector_path) = seed.vector_path.as_deref() else {
        return;
    };
    let Some(vector) = load_audit_vector(vector_path) else {
        return;
    };
    if vector.chain_length != vector.events.len() || vector.events.is_empty() {
        return;
    }

    let ids = vector
        .events
        .iter()
        .enumerate()
        .map(|(index, event)| {
            vector
                .events
                .get(index + 1)
                .and_then(|next| next.prev_hex.clone())
                .unwrap_or_else(|| format!("{}-{}-{index}", vector.description, event.description))
        })
        .collect::<Vec<_>>();

    if seed.entries.is_none() {
        seed.entries = Some(
            vector
                .events
                .iter()
                .enumerate()
                .map(|(index, event)| AuditEntrySeed {
                    id: Some(ids[index].clone()),
                    event_type: Some(event.event_type.clone()),
                    actor: Some(event.actor.clone()),
                    zone_id: Some(event.zone_id.clone()),
                    seq: Some(event.seq),
                    occurred_at: Some(event.occurred_at),
                    prev: event.prev_hex.clone(),
                    correlation_id: Some(format!("vector-corr-{index}")),
                    connector_id: None,
                    operation_id: None,
                    trace_id: None,
                    span_id: None,
                    flags: None,
                })
                .collect(),
        );
    }
    if seed.head.is_none() {
        let zone_id = vector
            .events
            .last()
            .map(|event| event.zone_id.clone())
            .unwrap_or_else(|| "z:work".to_string());
        seed.head = Some(AuditHeadSeed {
            zone_id: Some(zone_id.clone()),
            head_entry: ids.last().cloned(),
            head_seq: Some(vector.head_seq),
            coverage: Some(1.0),
            epoch_id: Some("vector-epoch".to_string()),
            signature_count: Some(1),
        });
        if seed.zone_filter.is_none() {
            seed.zone_filter = Some(zone_id);
        }
    }
}

pub(crate) fn apply_tampering(seed: &mut AuditSeed) {
    let (Some(entries), tamper) = (seed.entries.as_mut(), seed.tamper.as_deref()) else {
        return;
    };

    for item in tamper.iter().take(super::MAX_ENTRIES) {
        match item.action.as_deref() {
            Some("duplicate_seq") => {
                if let Some(index) = item.index
                    && let Some(target) = item.target
                    && let Some(target_seq) = entries.get(target).and_then(|entry| entry.seq)
                    && let Some(entry) = entries.get_mut(index)
                {
                    entry.seq = Some(item.seq.unwrap_or(target_seq));
                }
            }
            Some("break_prev") => {
                if let Some(index) = item.index
                    && let Some(entry) = entries.get_mut(index)
                {
                    entry.prev = Some(
                        item.value
                            .clone()
                            .unwrap_or_else(|| "tampered-prev".to_string()),
                    );
                }
            }
            Some("timestamp_regression") => {
                if let Some(index) = item.index
                    && index > 0
                    && let Some(prev_ts) =
                        entries.get(index - 1).and_then(|entry| entry.occurred_at)
                    && let Some(entry) = entries.get_mut(index)
                {
                    entry.occurred_at = Some(item.occurred_at.unwrap_or(prev_ts.saturating_sub(1)));
                }
            }
            Some("zone_mismatch") => {
                if let Some(index) = item.index
                    && let Some(entry) = entries.get_mut(index)
                {
                    entry.zone_id =
                        Some(item.value.clone().unwrap_or_else(|| "z:public".to_string()));
                }
            }
            Some("head_mismatch") => {
                if let Some(head) = seed.head.as_mut() {
                    head.head_entry = Some(
                        item.value
                            .clone()
                            .unwrap_or_else(|| "wrong-tip".to_string()),
                    );
                }
            }
            Some("head_seq_mismatch") => {
                if let Some(head) = seed.head.as_mut() {
                    head.head_seq = Some(
                        item.seq
                            .unwrap_or_else(|| head.head_seq.unwrap_or(0).saturating_add(1)),
                    );
                }
            }
            _ => {}
        }
    }
}
