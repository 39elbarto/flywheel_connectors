//! Frozen-byte golden tests for fcp-mesh signing transcripts.
//!
//! These tests pin the exact byte layout of `signing_bytes()` for the two
//! gossip messages that cross peers and get authenticated:
//!
//! - [`GossipSummary`] — anti-entropy summary, signed by the announcing node
//! - [`RevocationPushMessage`] — priority gossip for revocation propagation
//!
//! Existing tests in `gossip.rs` only check that `signing_bytes()` is
//! deterministic and starts with the domain separator. They do NOT freeze
//! the byte layout, so a refactor that reordered fields, changed length
//! encoding (LE → BE, u32 → u64), or inserted a new field would silently
//! break wire-format compatibility with already-deployed peers — every old
//! signature would fail to verify, but every test would still pass.
//!
//! The golden snapshots in `snapshots/` lock down the exact transcript.
//! When you intentionally change the transcript (e.g. bump the domain
//! separator from V1 to V2):
//!
//!     UPDATE_GOLDENS=1 cargo insta test -p fcp-mesh
//!     cargo insta review        # human reviews every diff
//!     git add crates/fcp-mesh/tests/snapshots/
//!
//! Any other change MUST fail these tests.

use std::fmt::Write as _;

use fcp_prelude::{EpochId, ObjectId, TailscaleNodeId, ZoneId};
use fcp_mesh::gossip::{GossipSummary, RevocationPushMessage};

/// Deterministic fixture node ID — never change this in-place; bump the
/// fixture name and add a new test instead.
fn fixture_node() -> TailscaleNodeId {
    TailscaleNodeId::new("100.64.0.1")
}

/// Fixture: zero-everything summary — locks the prefix layout (domain
/// separator + length-prefixed strings + zero digests + zero counts +
/// empty IBLT + zero timestamp).
fn empty_summary() -> GossipSummary {
    GossipSummary {
        from: fixture_node(),
        zone_id: ZoneId::work(),
        epoch_id: EpochId::new("epoch-test-fixture"),
        object_filter_digest: [0u8; 32],
        symbol_filter_digest: [0u8; 32],
        object_count: 0,
        symbol_count: 0,
        iblt: Vec::new(),
        timestamp: 0,
        signature: None,
    }
}

/// Fixture: populated summary with non-zero digests, counts, and IBLT
/// payload — locks the rest of the layout that `empty_summary` can't see.
fn populated_summary() -> GossipSummary {
    GossipSummary {
        from: fixture_node(),
        zone_id: ZoneId::private(),
        epoch_id: EpochId::new("epoch-fixture-2"),
        object_filter_digest: [0xAA; 32],
        symbol_filter_digest: [0xBB; 32],
        object_count: 0x1234_5678,
        symbol_count: 0x9ABC_DEF0,
        iblt: (0..16).collect::<Vec<u8>>(),
        timestamp: 0x0011_2233_4455_6677,
        signature: None,
    }
}

/// Fixture: revocation push covering two object IDs, non-zero seq+ts.
fn populated_revocation_push() -> RevocationPushMessage {
    RevocationPushMessage::new(
        fixture_node(),
        ZoneId::work(),
        vec![
            ObjectId::from_unscoped_bytes(b"object-fixture-a"),
            ObjectId::from_unscoped_bytes(b"object-fixture-b"),
        ],
        0x1122_3344,
        0x5566_7788_99AA_BBCC,
    )
}

/// Render bytes as a hex dump with section labels for human review.
fn dump(label: &str, bytes: &[u8]) -> String {
    let mut out = String::new();
    out.push_str(label);
    out.push('\n');
    writeln!(&mut out, "len = {}", bytes.len()).expect("writing to String cannot fail");
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let hex: String = chunk
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let ascii: String = chunk
            .iter()
            .map(|b| {
                if b.is_ascii_graphic() || *b == b' ' {
                    *b as char
                } else {
                    '.'
                }
            })
            .collect();
        writeln!(&mut out, "{:04x}  {:48}  {}", i * 16, hex, ascii)
            .expect("writing to String cannot fail");
    }
    out
}

#[test]
fn gossip_summary_signing_bytes_layout_empty_fixture() {
    let bytes = empty_summary().signing_bytes();
    insta::assert_snapshot!(dump("GossipSummary::signing_bytes (empty fixture)", &bytes));
}

#[test]
fn gossip_summary_signing_bytes_layout_populated_fixture() {
    let bytes = populated_summary().signing_bytes();
    insta::assert_snapshot!(dump(
        "GossipSummary::signing_bytes (populated fixture)",
        &bytes
    ));
}

#[test]
fn revocation_push_signing_bytes_layout_populated_fixture() {
    let bytes = populated_revocation_push().signing_bytes();
    insta::assert_snapshot!(dump(
        "RevocationPushMessage::signing_bytes (populated fixture)",
        &bytes
    ));
}
