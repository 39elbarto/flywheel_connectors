#![no_main]

use std::sync::Arc;

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::{EpochId, NodeId as SignatureNodeId, NodeSignature, TailscaleNodeId, ZoneId};
use fcp_crypto::Ed25519SigningKey;
use fcp_mesh::{
    GossipConfig, GossipSummary, IbltPlaceholder, MeshNode, MeshNodeConfig, ObjectAdmissionClass,
};
use fcp_store::{
    MemoryObjectStore, MemoryObjectStoreConfig, MemorySymbolStore, MemorySymbolStoreConfig,
    ObjectAdmissionPolicy, QuarantineStore,
};
use fcp_tailscale::NodeId as PeerNodeId;
use libfuzzer_sys::fuzz_target;
use serde::Deserialize;

#[derive(Arbitrary, Debug, Deserialize)]
struct SummaryInput {
    now_secs: u64,
    timestamp: u64,
    object_filter_digest: [u8; 32],
    symbol_filter_digest: [u8; 32],
    object_count: u32,
    symbol_count: u32,
    iblt: Vec<u8>,
    iblt_mode: u8,
    summary_ttl_secs: u16,
    max_objects_per_summary: u16,
    max_symbols_per_summary: u16,
    reconciliation_batch_size: u8,
    epoch_suffix: u16,
}

fn test_node(config: GossipConfig) -> MeshNode {
    let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
    let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
    let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));
    MeshNode::new(
        MeshNodeConfig::new("node-1")
            .with_gossip_config(config)
            .with_sender_instance_id(7),
        object_store,
        symbol_store,
        quarantine_store,
    )
}

fn summary_iblt(mode: u8, raw: &[u8], max_iblt_bytes: usize) -> Vec<u8> {
    match mode % 4 {
        0 => b"[]".to_vec(),
        1 => b"not-json".to_vec(),
        2 => vec![0u8; max_iblt_bytes.saturating_add(1)],
        _ => raw
            .iter()
            .copied()
            .take(max_iblt_bytes.saturating_add(32).min(4096))
            .collect(),
    }
}

fn accepted_summary(summary: &GossipSummary, config: &GossipConfig, now_secs: u64) -> bool {
    if summary.is_stale(now_secs, config.summary_ttl_secs) {
        return false;
    }
    if summary.object_count as usize > config.max_objects_per_summary
        || summary.symbol_count as usize > config.max_symbols_per_summary
    {
        return false;
    }
    IbltPlaceholder::decode_with_limits(
        &summary.iblt,
        config.reconciliation_batch_size,
        config.max_iblt_bytes(),
    )
    .is_ok()
}

fuzz_target!(|data: &[u8]| {
    let input = if let Ok(seed) = serde_json::from_slice::<SummaryInput>(data) {
        seed
    } else {
        let mut unstructured = Unstructured::new(data);
        let Ok(seed) = SummaryInput::arbitrary(&mut unstructured) else {
            return;
        };
        seed
    };

    let config = GossipConfig {
        summary_ttl_secs: u64::from(input.summary_ttl_secs % 300).saturating_add(1),
        max_objects_per_summary: usize::from(
            (input.max_objects_per_summary % 128).saturating_add(1),
        ),
        max_symbols_per_summary: usize::from(
            (input.max_symbols_per_summary % 256).saturating_add(1),
        ),
        reconciliation_batch_size: usize::from(
            (input.reconciliation_batch_size % 32).saturating_add(1),
        ),
        ..GossipConfig::default()
    };
    let mut node = test_node(config.clone());

    let signing_key = match Ed25519SigningKey::from_bytes(&[7u8; 32]) {
        Ok(key) => key,
        Err(_) => return,
    };
    node.register_peer_signing_key(PeerNodeId::new("peer-1"), signing_key.verifying_key());

    let mut summary = GossipSummary {
        from: TailscaleNodeId::new("peer-1"),
        zone_id: ZoneId::work(),
        epoch_id: EpochId::new(format!("epoch-{}", input.epoch_suffix)),
        object_filter_digest: input.object_filter_digest,
        symbol_filter_digest: input.symbol_filter_digest,
        object_count: input.object_count,
        symbol_count: input.symbol_count,
        iblt: summary_iblt(input.iblt_mode, &input.iblt, config.max_iblt_bytes()),
        timestamp: input.timestamp,
        signature: None,
    };
    summary.signature = Some(NodeSignature::new(
        SignatureNodeId::new("peer-1"),
        signing_key.sign(&summary.signing_bytes()).to_bytes(),
        summary.timestamp,
    ));

    let should_install_peer_state = accepted_summary(&summary, &config, input.now_secs);
    let before_updates = node.metrics().gossip_updates;
    let result = node.handle_summary(summary, input.now_secs);
    assert!(
        result.is_ok(),
        "valid signature should reach post-verify summary handling"
    );
    assert_eq!(
        node.metrics().gossip_updates,
        before_updates.saturating_add(1)
    );

    let prune_at_ms = input
        .now_secs
        .saturating_add(config.summary_ttl_secs)
        .saturating_add(2)
        .saturating_mul(1000);
    let pruned = node.prune_stale_state(prune_at_ms);

    if should_install_peer_state {
        assert!(
            pruned >= 1,
            "accepted summary should leave stale gossip peer state to prune"
        );
    } else {
        assert_eq!(pruned, 0, "rejected summary must not install peer state");
    }

    let _ = node.announce_symbol(
        &ZoneId::work(),
        &fcp_core::ObjectId::from_bytes([0xAA; 32]),
        0,
        ObjectAdmissionClass::Admitted,
        input.now_secs.saturating_mul(1000),
    );
});
