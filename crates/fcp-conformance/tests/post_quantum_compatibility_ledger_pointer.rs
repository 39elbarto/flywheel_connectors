//! Post-quantum conformance: compatibility-ledger latest pointer V1 to V2 upgrade safety.

use std::fs;
use std::path::{Path, PathBuf};

use fcp_evidence::{
    CompatibilityLedgerBody, CompatibilityLedgerRoot, MeshCompatibilityLedger, MigrationPhase,
};
use fcp_store::{CompatibilityLedgerStore, DurableCompatibilityLedgerStore};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
struct LegacyV1Pointer {
    mesh_id: String,
    root: CompatibilityLedgerRoot,
}

#[derive(Debug, Deserialize)]
struct V2Pointer {
    mesh_id: String,
    root: CompatibilityLedgerRoot,
    sequence: u64,
    published_at_ms: u64,
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_nanos();
    path.push(format!("{prefix}-{}-{now}", std::process::id()));
    path
}

fn ledger(
    mesh_id: &str,
    epoch: u64,
    previous_root: Option<CompatibilityLedgerRoot>,
) -> MeshCompatibilityLedger {
    let mut body = CompatibilityLedgerBody::new(mesh_id, epoch, MigrationPhase::DualAdvertise);
    body.previous_root = previous_root;
    body.valid_from_ms = 1_700_000_000_000 + epoch;
    body.expires_at_ms = 1_800_000_000_000 + epoch;
    MeshCompatibilityLedger::unsigned(body)
}

fn only_latest_pointer_path(root: &Path) -> PathBuf {
    let latest_dir = root.join("latest");
    let mut paths: Vec<PathBuf> = fs::read_dir(&latest_dir)
        .expect("latest dir exists")
        .map(|entry| entry.expect("latest entry").path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("cbor"))
        .collect();
    paths.sort();
    assert_eq!(paths.len(), 1, "expected exactly one latest pointer file");
    paths.remove(0)
}

#[test]
fn compatibility_ledger_v1_pointer_is_upgraded_to_high_water_mark_v2_pointer() {
    let root = unique_temp_dir("fcp-conformance-pq-ledger-pointer");
    let mesh_id = "mesh-pointer-upgrade-safety";
    let store = DurableCompatibilityLedgerStore::open(&root).expect("open fresh store");
    let epoch1 = ledger(mesh_id, 1, None);
    let root1 = store.put_ledger(epoch1).expect("persist epoch 1");
    let epoch2 = ledger(mesh_id, 2, Some(root1));
    let root2 = store.put_ledger(epoch2).expect("persist epoch 2");

    let pointer_path = only_latest_pointer_path(&root);
    let legacy_pointer = LegacyV1Pointer {
        mesh_id: mesh_id.to_owned(),
        root: root1,
    };
    let legacy_bytes = fcp_cbor::to_canonical_cbor(&legacy_pointer).expect("encode V1 pointer");
    fs::write(&pointer_path, legacy_bytes).expect("overwrite latest pointer with V1 form");

    let reopened = DurableCompatibilityLedgerStore::open(&root).expect("reopen upgrades pointer");
    let latest = reopened
        .latest_ledger(mesh_id)
        .expect("latest ledger after V1 pointer replay");
    assert_eq!(
        latest.epoch(),
        2,
        "V1 pointer must not silently downgrade below signed-ledger high-water mark"
    );

    let repaired_bytes = fs::read(&pointer_path).expect("read repaired pointer");
    let repaired: V2Pointer =
        ciborium::from_reader(repaired_bytes.as_slice()).expect("decode repaired V2 pointer");
    assert_eq!(repaired.mesh_id, mesh_id);
    assert_eq!(repaired.root, root2);
    assert_eq!(repaired.sequence, 2);
    assert!(
        repaired.published_at_ms > 0,
        "V2 pointer repair must populate forensic published_at_ms"
    );
}
