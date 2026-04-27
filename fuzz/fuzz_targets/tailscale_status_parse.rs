#![no_main]

//! Fuzz target for `fcp_tailscale::TailscaleStatus` JSON deserialization
//! and `TailscaleStatus::peers()` consistency check.
//!
//! `TailscaleStatus` is the wire-supplied output of `tailscaled`'s
//! LocalAPI. A compromised local socket, an MITM on the loopback HTTP
//! variant, or a malicious mock in tests could all feed adversarial
//! JSON. The `peers()` accessor performs two safety checks that close
//! distinct attack vectors:
//!
//!   - **Map-key / embedded-id consistency**: the outer
//!     `peer: HashMap<String, PeerInfo>` is supposed to be keyed by the
//!     same id that `PeerInfo::id` carries. A malicious tailscaled could
//!     ship a map where the key disagrees with the embedded id —
//!     letting a peer claim a different identity at lookup time vs.
//!     identity-binding time. `peers()` rejects with `ParseError`.
//!   - **Duplicate detection**: `HashMap<String, _>` enforces unique
//!     raw-string keys, but the canonical `NodeId::try_new` may
//!     collapse two distinct raw keys onto the same canonical id (or,
//!     in the MITM case, the JSON could itself contain a duplicate
//!     after `serde_json` deserialization to a `HashMap`). `peers()`
//!     catches the dedup-after-canonicalization case via the second
//!     `insert.is_some()` check.
//!
//! Existing `fuzz_tailscale_acl` covers Tag/Zone mapping but NOT this
//! status-parse surface.
//!
//! Properties asserted:
//!
//!   1. `serde_json::from_slice::<TailscaleStatus>` is panic-free over
//!      arbitrary JSON bytes.
//!   2. `TailscaleStatus::peers()` is panic-free on every deserialized
//!      status.
//!   3. **Map-key/id consistency is enforced**: a hand-crafted
//!      `TailscaleStatus` whose outer key disagrees with the embedded
//!      `peer.id` MUST be rejected by `peers()`. Verified on every
//!      iteration as a constructed regression anchor.
//!   4. `PeerInfo::fcp_tags()` is panic-free over arbitrary tag input.

use arbitrary::{Arbitrary, Unstructured};
use fcp_tailscale::{PeerInfo, SelfNode, TailscaleStatus};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::sync::Once;

const MAX_INPUT_BYTES: usize = 16 * 1024;

static CONSISTENCY_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    json_bytes: Vec<u8>,
}

fuzz_target!(|data: &[u8]| {
    CONSISTENCY_ANCHOR.call_once(assert_consistency_check_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    // ── PROPERTY 1: panic-free JSON deserialization ────────────────────
    let json: &[u8] = if input.json_bytes.len() > MAX_INPUT_BYTES {
        &input.json_bytes[..MAX_INPUT_BYTES]
    } else {
        &input.json_bytes[..]
    };

    let Ok(status) = serde_json::from_slice::<TailscaleStatus>(json) else {
        return;
    };

    // ── PROPERTY 2: peers() never panics ───────────────────────────────
    // It MAY return Err — invalid NodeId in a key/id, or map-key vs.
    // embedded-id disagreement, or duplicate canonical id.
    let _ = status.peers();

    // ── PROPERTY 4: tag filtering panic-free ───────────────────────────
    for peer in status.peer.values() {
        let _ = peer.tailscale_tags();
        let _ = peer.fcp_tags();
        let _ = peer.node_id();
    }
});

/// Hand-crafted regression anchor verifying that the consistency check
/// at TailscaleStatus::peers() (client.rs:91-96) actually fires when
/// the map key disagrees with the embedded peer.id. Run once per
/// process so we always catch a regression that drops the check.
fn assert_consistency_check_anchored() {
    let benign = mk_peer("node-real");
    let mismatched_key_id = "node-impersonator".to_string();

    let status = TailscaleStatus {
        backend_state: "Running".to_string(),
        self_node: mk_self_node("node-self"),
        peer: HashMap::from([(mismatched_key_id, benign)]),
        user: None,
        tailnet: None,
    };

    let result = status.peers();
    assert!(
        result.is_err(),
        "TailscaleStatus::peers() MUST reject when outer map key disagrees \
         with embedded peer.id (impersonation surface) — see client.rs:91-96"
    );

    // Anchor: a consistent status MUST be accepted, otherwise the
    // rejection assertion above is uninformative.
    let consistent = TailscaleStatus {
        backend_state: "Running".to_string(),
        self_node: mk_self_node("node-self"),
        peer: HashMap::from([("node-real".to_string(), mk_peer("node-real"))]),
        user: None,
        tailnet: None,
    };
    consistent.peers().expect(
        "consistent TailscaleStatus MUST be accepted; if this trips, \
                 peers() has become over-restrictive and the regression catalog \
                 is unsound",
    );
}

fn mk_self_node(id: &str) -> SelfNode {
    SelfNode {
        id: id.to_string(),
        public_key: "nodekey:abcdef".to_string(),
        host_name: "host".to_string(),
        dns_name: "host.example.ts.net.".to_string(),
        tailscale_ips: vec!["100.64.0.1".parse().expect("static ip")],
        tags: vec![],
        online: true,
    }
}

fn mk_peer(id: &str) -> PeerInfo {
    PeerInfo {
        id: id.to_string(),
        public_key: "nodekey:abcdef".to_string(),
        host_name: "peer".to_string(),
        dns_name: "peer.example.ts.net.".to_string(),
        tailscale_ips: vec!["100.64.0.2".parse().expect("static ip")],
        tags: vec![],
        online: true,
        os: None,
        last_seen: None,
    }
}
