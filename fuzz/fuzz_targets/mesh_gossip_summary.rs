#![no_main]

use std::sync::Arc;

use arbitrary::Arbitrary;
use fcp_core::{EpochId, NodeId as SignatureNodeId, NodeSignature, TailscaleNodeId, ZoneId};
use fcp_crypto::Ed25519SigningKey;
use fcp_mesh::{GossipMessage, GossipSummary, MeshNode, MeshNodeConfig, MeshNodeError};
use fcp_store::{
    MemoryObjectStore, MemoryObjectStoreConfig, MemorySymbolStore, MemorySymbolStoreConfig,
    ObjectAdmissionPolicy, QuarantineStore,
};
use fcp_tailscale::NodeId as PeerNodeId;
use libfuzzer_sys::fuzz_target;

const MAX_IBLT_BYTES: usize = 4096;

#[derive(Arbitrary, Debug)]
struct SummaryInput {
    object_filter_digest: [u8; 32],
    symbol_filter_digest: [u8; 32],
    object_count: u32,
    symbol_count: u32,
    iblt: Vec<u8>,
    timestamp: u64,
    signing_seed: [u8; 32],
    alternate_seed: [u8; 32],
    random_signature: [u8; 64],
    epoch_suffix: u16,
    mode: u8,
}

fn test_node(name: &str) -> MeshNode {
    let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
    let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
    let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));
    MeshNode::new(
        MeshNodeConfig::new(name).with_sender_instance_id(42),
        object_store,
        symbol_store,
        quarantine_store,
    )
}

fn build_signature(
    mode: u8,
    summary: &GossipSummary,
    signing_seed: &[u8; 32],
    alternate_seed: &[u8; 32],
    random_signature: [u8; 64],
) -> Option<NodeSignature> {
    match mode % 5 {
        0 => {
            let signing_key = Ed25519SigningKey::from_bytes(signing_seed).ok()?;
            Some(NodeSignature::new(
                SignatureNodeId::new("peer-1"),
                signing_key.sign(&summary.signing_bytes()).to_bytes(),
                summary.timestamp,
            ))
        }
        1 => {
            let signing_key = Ed25519SigningKey::from_bytes(alternate_seed).ok()?;
            Some(NodeSignature::new(
                SignatureNodeId::new("peer-1"),
                signing_key.sign(&summary.signing_bytes()).to_bytes(),
                summary.timestamp,
            ))
        }
        2 => {
            let signing_key = Ed25519SigningKey::from_bytes(signing_seed).ok()?;
            Some(NodeSignature::new(
                SignatureNodeId::new("peer-2"),
                signing_key.sign(&summary.signing_bytes()).to_bytes(),
                summary.timestamp,
            ))
        }
        3 => None,
        _ => Some(NodeSignature::new(
            SignatureNodeId::new("peer-1"),
            random_signature,
            summary.timestamp,
        )),
    }
}

fuzz_target!(|input: SummaryInput| {
    let mut node = test_node("node-1");
    let registered_key = match Ed25519SigningKey::from_bytes(&input.signing_seed) {
        Ok(key) => key,
        Err(_) => return,
    };
    node.register_peer_signing_key(PeerNodeId::new("peer-1"), registered_key.verifying_key());

    let mut summary = GossipSummary {
        from: TailscaleNodeId::new("peer-1"),
        zone_id: ZoneId::work(),
        epoch_id: EpochId::new(format!("epoch-{}", input.epoch_suffix)),
        object_filter_digest: input.object_filter_digest,
        symbol_filter_digest: input.symbol_filter_digest,
        object_count: input.object_count,
        symbol_count: input.symbol_count,
        iblt: input.iblt.into_iter().take(MAX_IBLT_BYTES).collect(),
        timestamp: input.timestamp,
        signature: None,
    };
    summary.signature = build_signature(
        input.mode,
        &summary,
        &input.signing_seed,
        &input.alternate_seed,
        input.random_signature,
    );

    let result = node.handle_gossip_message(GossipMessage::Summary(summary), input.timestamp);
    match input.mode % 5 {
        0 => {
            assert!(result.is_ok(), "valid signed summary should verify");
        }
        1 | 3 | 4 => {
            assert!(matches!(
                result,
                Err(MeshNodeError::PeerSignatureInvalid { .. })
            ));
        }
        2 => {
            assert!(matches!(result, Err(MeshNodeError::SignatureNodeMismatch { .. })));
        }
        _ => unreachable!(),
    }
});
