use super::{HeaderMutationSeed, ObjectSeed, PlacementSeed, StoreSeed, SymbolSeed};
use fcp_core::{ObjectId, ZoneId};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Deserialize, Serialize)]
struct CheckpointVector {
    zone_id: String,
    prev_checkpoint_id: String,
    audit_head_id: String,
    revocation_head_id: String,
    zone_definition_head: String,
    zone_policy_head: String,
    active_zone_key_manifest: String,
    proposed_seq: u64,
}

fn core_vectors_dir() -> PathBuf {
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

fn load_vector_json<T: for<'de> Deserialize<'de>>(name: &str) -> Option<T> {
    let path = safe_vector_path(&core_vectors_dir(), name)?;
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn load_vector_bytes(name: &str) -> Option<Vec<u8>> {
    let path = safe_vector_path(&core_vectors_dir(), name)?;
    fs::read(path).ok()
}

pub(crate) fn parse_object_id_hex(value: &str) -> Option<ObjectId> {
    let bytes = hex::decode(value).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&bytes);
    Some(ObjectId::from_bytes(raw))
}

fn vector_hex_body(seed: &StoreSeed, vector: &CheckpointVector) -> String {
    seed.body_vector
        .as_deref()
        .and_then(load_vector_bytes)
        .or_else(|| serde_json::to_vec(vector).ok())
        .map(|bytes| {
            hex::encode(
                bytes
                    .into_iter()
                    .take(super::MAX_BODY_BYTES)
                    .collect::<Vec<_>>(),
            )
        })
        .unwrap_or_default()
}

fn vector_symbols(body_hex: &str, available: usize, node_base: u64) -> Vec<SymbolSeed> {
    let bytes = hex::decode(body_hex).unwrap_or_default();
    (0..available.min(super::MAX_SYMBOLS_PER_OBJECT))
        .map(|index| {
            let chunk = if bytes.is_empty() {
                vec![u8::try_from(index).unwrap_or(0); 4]
            } else {
                let start = (index * 4) % bytes.len();
                let end = (start + 4).min(bytes.len());
                bytes[start..end].to_vec()
            };
            SymbolSeed {
                esi: Some(index as u32),
                data_hex: Some(hex::encode(chunk)),
                source_node: Some(node_base + index as u64),
                zone_id: None,
                stored_at: Some(1_000 + index as u64),
            }
        })
        .collect()
}

pub(crate) fn hydrate_vector_objects(
    seed: &StoreSeed,
) -> Option<(ZoneId, Vec<ObjectSeed>, Option<usize>)> {
    let vector = load_vector_json::<CheckpointVector>(seed.checkpoint_vector.as_deref()?)?;
    let primary_zone = seed
        .zone_id
        .as_deref()
        .and_then(|zone| zone.parse::<ZoneId>().ok())
        .or_else(|| vector.zone_id.parse::<ZoneId>().ok())
        .unwrap_or_else(ZoneId::work);
    let body_hex = vector_hex_body(seed, &vector);

    let ids = [
        vector.prev_checkpoint_id.clone(),
        vector.audit_head_id.clone(),
        vector.revocation_head_id.clone(),
        vector.zone_definition_head.clone(),
        vector.zone_policy_head.clone(),
        vector.active_zone_key_manifest.clone(),
    ];
    if ids.iter().any(|value| parse_object_id_hex(value).is_none()) {
        return None;
    }

    let objects = vec![
        ObjectSeed {
            id_hex: Some(vector.prev_checkpoint_id),
            id_byte: None,
            zone_id: Some(primary_zone.to_string()),
            body_hex: Some(body_hex.clone()),
            refs: Some(vec![1, 2, 3, 4, 5]),
            foreign_refs: Some(vec![]),
            retention: Some("pinned".to_string()),
            lease_expires_at: Some(0),
            ttl_secs: Some(vector.proposed_seq),
            placement: Some(PlacementSeed {
                min_nodes: Some(2),
                max_node_fraction_bps: Some(6_000),
                target_coverage_bps: Some(9_500),
                min_source_diversity: Some(2),
            }),
            include_policy: Some(true),
            source_symbols: Some(6),
            symbol_size: Some(16),
            symbols: Some(vector_symbols(&body_hex, 3, 1)),
        },
        ObjectSeed {
            id_hex: Some(vector.audit_head_id),
            id_byte: None,
            zone_id: Some(primary_zone.to_string()),
            body_hex: Some(body_hex.clone()),
            refs: Some(vec![]),
            foreign_refs: Some(vec![]),
            retention: Some("ephemeral".to_string()),
            lease_expires_at: Some(0),
            ttl_secs: Some(120),
            placement: Some(PlacementSeed {
                min_nodes: Some(2),
                max_node_fraction_bps: Some(5_000),
                target_coverage_bps: Some(9_000),
                min_source_diversity: Some(2),
            }),
            include_policy: Some(true),
            source_symbols: Some(4),
            symbol_size: Some(16),
            symbols: Some(vector_symbols(&body_hex, 1, 10)),
        },
        ObjectSeed {
            id_hex: Some(vector.revocation_head_id),
            id_byte: None,
            zone_id: Some(primary_zone.to_string()),
            body_hex: Some(body_hex.clone()),
            refs: Some(vec![]),
            foreign_refs: Some(vec![]),
            retention: Some("lease".to_string()),
            lease_expires_at: Some(500),
            ttl_secs: Some(60),
            placement: Some(PlacementSeed {
                min_nodes: Some(1),
                max_node_fraction_bps: Some(10_000),
                target_coverage_bps: Some(8_000),
                min_source_diversity: Some(1),
            }),
            include_policy: Some(true),
            source_symbols: Some(3),
            symbol_size: Some(16),
            symbols: Some(vector_symbols(&body_hex, 0, 20)),
        },
        ObjectSeed {
            id_hex: Some(vector.zone_definition_head),
            id_byte: None,
            zone_id: Some(primary_zone.to_string()),
            body_hex: Some(body_hex.clone()),
            refs: Some(vec![]),
            foreign_refs: Some(vec![]),
            retention: Some("ephemeral".to_string()),
            lease_expires_at: Some(0),
            ttl_secs: Some(240),
            placement: None,
            include_policy: Some(false),
            source_symbols: Some(2),
            symbol_size: Some(16),
            symbols: Some(vector_symbols(&body_hex, 2, 30)),
        },
        ObjectSeed {
            id_hex: Some(vector.zone_policy_head),
            id_byte: None,
            zone_id: Some(primary_zone.to_string()),
            body_hex: Some(body_hex.clone()),
            refs: Some(vec![]),
            foreign_refs: Some(vec![]),
            retention: Some("ephemeral".to_string()),
            lease_expires_at: Some(0),
            ttl_secs: Some(180),
            placement: None,
            include_policy: Some(false),
            source_symbols: Some(2),
            symbol_size: Some(16),
            symbols: Some(vector_symbols(&body_hex, 1, 40)),
        },
        ObjectSeed {
            id_hex: Some(vector.active_zone_key_manifest),
            id_byte: None,
            zone_id: Some(primary_zone.to_string()),
            body_hex: Some(body_hex.clone()),
            refs: Some(vec![]),
            foreign_refs: Some(vec![]),
            retention: Some("lease".to_string()),
            lease_expires_at: Some(250),
            ttl_secs: Some(90),
            placement: Some(PlacementSeed {
                min_nodes: Some(2),
                max_node_fraction_bps: Some(7_500),
                target_coverage_bps: Some(8_500),
                min_source_diversity: Some(2),
            }),
            include_policy: Some(true),
            source_symbols: Some(4),
            symbol_size: Some(16),
            symbols: Some(vector_symbols(&body_hex, 1, 50)),
        },
    ];
    Some((primary_zone, objects, Some(0)))
}

pub(crate) fn apply_header_mutations(
    objects: &mut [ObjectSeed],
    mutations: Option<&[HeaderMutationSeed]>,
) {
    for mutation in mutations.unwrap_or(&[]).iter().take(super::MAX_OBJECTS) {
        let Some(index) = mutation.index else {
            continue;
        };
        let Some(object) = objects.get_mut(index) else {
            continue;
        };
        match mutation.action.as_deref() {
            Some("clear_refs") => object.refs = Some(Vec::new()),
            Some("append_ref") => {
                if let Some(target) = mutation.target {
                    object.refs.get_or_insert_with(Vec::new).push(target);
                }
            }
            Some("append_foreign_ref") => {
                if let Some(target) = mutation.target {
                    object
                        .foreign_refs
                        .get_or_insert_with(Vec::new)
                        .push(target);
                }
            }
            Some("foreign_zone") => {
                object.zone_id = Some(
                    mutation
                        .zone_id
                        .clone()
                        .unwrap_or_else(|| "z:public".to_string()),
                );
            }
            Some("expire_lease") => {
                object.retention = Some("lease".to_string());
                object.lease_expires_at = Some(0);
            }
            Some("pin_retention") => object.retention = Some("pinned".to_string()),
            Some("drop_policy") => {
                object.include_policy = Some(false);
                object.placement = None;
            }
            Some("set_ttl") => object.ttl_secs = mutation.ttl_secs,
            _ => {}
        }
    }
}
