#![no_main]

//! Negative-path fuzz for the gossip-message signature gate.
//!
//! The existing `mesh_post_verify_{summary,symbol_ack,decode_status}` targets
//! all sign their payloads with the registered key and prove the post-verify
//! path is reachable. That's the positive side of the contract. This target
//! exercises the negative side: given a VALID signing key, we sign a
//! payload, then systematically corrupt one of the signed-transcript inputs
//! BEFORE handing the message to `MeshNode::handle_summary`. A correct
//! implementation must reject EVERY corruption with `PeerSignatureInvalid`;
//! any accept is a signature-gate bypass.
//!
//! Covered corruption modes:
//!   - flip a byte inside the signature (wrong-signature detection);
//!   - rotate `object_filter_digest` / `symbol_filter_digest` (content
//!     tampering under a legitimate signature);
//!   - swap the `from` field to a different peer id (impersonation);
//!   - clear the signature (unsigned message);
//!   - sign with the "wrong" key (no peer registered for that id).
//!
//! The fuzzer does NOT test positive acceptance — that's the job of
//! `fuzz_mesh_post_verify_summary`. Keeping the two targets separate makes
//! CI regressions maximally diagnosable: a failure here is specifically a
//! signature-gate bypass, never a post-verify bookkeeping bug.

use std::sync::Arc;

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::{EpochId, NodeId as SignatureNodeId, NodeSignature, TailscaleNodeId, ZoneId};
use fcp_crypto::Ed25519SigningKey;
use fcp_mesh::{GossipConfig, GossipSummary, MeshNode, MeshNodeConfig, MeshNodeError};
use fcp_store::{
    MemoryObjectStore, MemoryObjectStoreConfig, MemorySymbolStore, MemorySymbolStoreConfig,
    ObjectAdmissionPolicy, QuarantineStore,
};
use fcp_tailscale::NodeId as PeerNodeId;
use libfuzzer_sys::fuzz_target;
use serde::Deserialize;

#[derive(Arbitrary, Debug, Deserialize)]
struct CorruptionInput {
    now_secs: u64,
    timestamp: u64,
    object_filter_digest: [u8; 32],
    symbol_filter_digest: [u8; 32],
    object_count: u32,
    symbol_count: u32,
    epoch_suffix: u16,
    /// Which corruption mode to apply to the signed summary.
    /// Modulo to pick a branch; exhausting the space is cheap since each
    /// mode is a distinct semantic attack the gate must reject.
    corruption_mode: u8,
    /// Byte index inside the 64-byte Ed25519 signature to flip (when mode
    /// selects signature-bit corruption).
    sig_flip_byte: u8,
}

fn test_node(config: GossipConfig) -> MeshNode {
    let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
    let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
    let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));
    MeshNode::new(
        MeshNodeConfig::new("node-local")
            .with_gossip_config(config)
            .with_sender_instance_id(7),
        object_store,
        symbol_store,
        quarantine_store,
    )
}

fuzz_target!(|data: &[u8]| {
    let input = if let Ok(seed) = serde_json::from_slice::<CorruptionInput>(data) {
        seed
    } else {
        let mut unstructured = Unstructured::new(data);
        let Ok(seed) = CorruptionInput::arbitrary(&mut unstructured) else {
            return;
        };
        seed
    };

    let config = GossipConfig::default();
    let mut node = test_node(config.clone());

    // Register ONE peer's verifying key under "peer-1". Everything signed
    // by this key MUST be accepted only when the transcript is untouched
    // and the `from` field binds back to "peer-1".
    let Ok(signing_key) = Ed25519SigningKey::from_bytes(&[7u8; 32]) else {
        return;
    };
    node.register_peer_signing_key(PeerNodeId::new("peer-1"), signing_key.verifying_key());

    // Build a canonical, well-formed summary that WOULD pass if nothing
    // were corrupted. `iblt = "[]"` keeps the IBLT decode trivial so the
    // signature gate is the only variable being tested.
    let mut summary = GossipSummary {
        from: TailscaleNodeId::new("peer-1"),
        zone_id: ZoneId::work(),
        epoch_id: EpochId::new(format!("epoch-{}", input.epoch_suffix)),
        object_filter_digest: input.object_filter_digest,
        symbol_filter_digest: input.symbol_filter_digest,
        object_count: input.object_count,
        symbol_count: input.symbol_count,
        iblt: b"[]".to_vec(),
        timestamp: input.timestamp,
        signature: None,
    };
    let signing_bytes = summary.signing_bytes();
    let mut sig_bytes = signing_key.sign(&signing_bytes).to_bytes();

    match input.corruption_mode % 6 {
        0 => {
            // Mode 0: flip one bit in the signature. Must be rejected.
            let idx = usize::from(input.sig_flip_byte) % sig_bytes.len();
            sig_bytes[idx] ^= 0x80;
            summary.signature = Some(NodeSignature::new(
                SignatureNodeId::new("peer-1"),
                sig_bytes,
                summary.timestamp,
            ));
        }
        1 => {
            // Mode 1: sign legit bytes, then tamper the object_filter_digest
            // AFTER signing. Content no longer matches signed transcript.
            summary.signature = Some(NodeSignature::new(
                SignatureNodeId::new("peer-1"),
                sig_bytes,
                summary.timestamp,
            ));
            // Mutate one digest byte to guarantee divergence.
            let idx = usize::from(input.sig_flip_byte) % summary.object_filter_digest.len();
            summary.object_filter_digest[idx] ^= 0xFF;
        }
        2 => {
            // Mode 2: tamper the symbol_filter_digest post-signing.
            summary.signature = Some(NodeSignature::new(
                SignatureNodeId::new("peer-1"),
                sig_bytes,
                summary.timestamp,
            ));
            let idx = usize::from(input.sig_flip_byte) % summary.symbol_filter_digest.len();
            summary.symbol_filter_digest[idx] ^= 0xFF;
        }
        3 => {
            // Mode 3: impersonation. Sign with peer-1's key but stamp the
            // envelope `from` field as "peer-2". The signature bytes are
            // authentic but the sender binding is a lie. A correct gate
            // MUST reject because the verifying key lookup for "peer-2"
            // either fails or mismatches the signer.
            summary.from = TailscaleNodeId::new("peer-2");
            summary.signature = Some(NodeSignature::new(
                SignatureNodeId::new("peer-2"),
                sig_bytes,
                summary.timestamp,
            ));
        }
        4 => {
            // Mode 4: unsigned. The signature field is absent.
            summary.signature = None;
        }
        _ => {
            // Mode 5: sign with a DIFFERENT key than the one registered.
            let wrong_key = match Ed25519SigningKey::from_bytes(&[0x42u8; 32]) {
                Ok(k) => k,
                Err(_) => return,
            };
            let wrong_sig = wrong_key.sign(&summary.signing_bytes()).to_bytes();
            summary.signature = Some(NodeSignature::new(
                SignatureNodeId::new("peer-1"),
                wrong_sig,
                summary.timestamp,
            ));
        }
    }

    let before_updates = node.metrics().gossip_updates;
    let result = node.handle_summary(summary, input.now_secs);
    // Every corruption mode above is a semantic violation of the signed
    // transcript. The gate MUST reject.
    assert!(
        matches!(
            result,
            Err(MeshNodeError::PeerSignatureInvalid { .. })
                | Err(MeshNodeError::RecipientMismatch { .. })
                | Err(MeshNodeError::UnknownPeer { .. })
        ),
        "corruption mode {} produced an unexpected outcome: {:?}",
        input.corruption_mode % 6,
        result,
    );
    assert_eq!(
        node.metrics().gossip_updates,
        before_updates,
        "corrupted summary must not bump gossip_updates (reject must fire \
         before post-verify state changes)"
    );
});
