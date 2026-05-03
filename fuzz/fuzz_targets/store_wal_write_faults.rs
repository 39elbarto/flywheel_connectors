#![no_main]

//! Stateful fuzz target for fcp-store durable WRITE-path fault tolerance.
//!
//! This complements `store_wal_recovery`: instead of starting with arbitrary
//! attacker bytes, it first drives the real durable writers (`put`,
//! `put_object_meta`, `put_symbol`, and explicit checkpoints), then corrupts the
//! files those writers produced. The target models the failure classes from
//! `flywheel_connectors-7fjv9`:
//!
//! - kill-9 style torn WAL tails after a successful append;
//! - partial-page writes against object and symbol-map snapshots/WALs;
//! - byte corruption windows in writer-produced JSONL/envelope files;
//! - APFS atomic-rename leftovers via stale checkpoint temp-file collisions.
//!
//! Oracle: reopen must either reject with a typed error or recover only objects
//! and symbols that were successfully written by the prefix of this run. A
//! successful recovery must be fixed-point on a second reopen.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use arbitrary::{Arbitrary, Unstructured};
use bytes::Bytes;
use fcp_async_core::runtime::block_on_sync;
use fcp_cbor::SchemaId;
use fcp_core::{
    ObjectHeader, ObjectId, Provenance, RetentionClass, StorageMeta, StoredObject, ZoneId,
};
use fcp_store::{
    DurableObjectStore, DurableObjectStoreConfig, DurableSymbolStore, DurableSymbolStoreConfig,
    ObjectStore, ObjectSymbolMeta, ObjectTransmissionInfo, StoredSymbol, SymbolMeta, SymbolStore,
};
use libfuzzer_sys::fuzz_target;
use semver::Version;
use tempfile::TempDir;

const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_OBJECTS: usize = 6;
const MAX_BODY_BYTES: usize = 2048;
const MAX_SYMBOLS: usize = 6;
const MAX_SYMBOL_BYTES: usize = 256;
const MAX_TAIL_BYTES: usize = 512;
const PARTIAL_PAGE: usize = 4096;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    object_count: u8,
    symbol_count: u8,
    object_seed: u8,
    zone_choice: u8,
    checkpoint_mode: u8,
    mac_mode: u8,
    stale_temp_collisions: u8,
    object_fault: FaultSpec,
    symbol_fault: FaultSpec,
    body: Vec<u8>,
    tail: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
struct FaultSpec {
    target: u8,
    kind: u8,
    offset: u32,
    len: u16,
    byte: u8,
}

fn zone(choice: u8) -> ZoneId {
    match choice % 5 {
        0 => ZoneId::owner(),
        1 => ZoneId::private(),
        2 => ZoneId::work(),
        3 => ZoneId::community(),
        _ => ZoneId::public(),
    }
}

fn schema() -> SchemaId {
    SchemaId::new("fcp.fuzz", "DurableWriteFault", Version::new(1, 0, 0))
}

fn object_id(seed: u8, index: usize) -> ObjectId {
    let mut bytes = [seed; 32];
    bytes[0] = seed.wrapping_add(index as u8);
    bytes[31] = index as u8;
    ObjectId::from_bytes(bytes)
}

fn object(seed: u8, index: usize, zone_id: &ZoneId, body_seed: &[u8]) -> StoredObject {
    let mut body = body_seed
        .iter()
        .copied()
        .take(MAX_BODY_BYTES)
        .collect::<Vec<_>>();
    if body.is_empty() {
        body.extend_from_slice(&[seed.wrapping_add(index as u8); 32]);
    }
    StoredObject {
        object_id: object_id(seed, index),
        header: ObjectHeader {
            schema: schema(),
            zone_id: zone_id.clone(),
            created_at: 1_700_000_000_u64.saturating_add(index as u64),
            provenance: Provenance::new(zone_id.clone()),
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        },
        body,
        storage: StorageMeta {
            retention: RetentionClass::Pinned,
        },
    }
}

fn symbol_meta(object_id: ObjectId, zone_id: &ZoneId, source_symbols: u32) -> ObjectSymbolMeta {
    let symbol_size = 64_u16;
    ObjectSymbolMeta {
        object_id,
        zone_id: zone_id.clone(),
        oti: ObjectTransmissionInfo {
            transfer_length: u64::from(source_symbols) * u64::from(symbol_size),
            symbol_size,
            source_blocks: 1,
            sub_blocks: 1,
            alignment: 8,
            payload_hash: None,
        },
        source_symbols,
        first_symbol_at: 1_700_000_000,
    }
}

fn symbol(meta: &ObjectSymbolMeta, esi: u32, fill: u8, bytes: &[u8]) -> StoredSymbol {
    let mut data = bytes
        .iter()
        .copied()
        .take(MAX_SYMBOL_BYTES)
        .collect::<Vec<_>>();
    data.resize(usize::from(meta.oti.symbol_size), fill);
    StoredSymbol {
        meta: SymbolMeta {
            object_id: meta.object_id,
            esi,
            zone_id: meta.zone_id.clone(),
            source_node: Some(7),
            stored_at: 1_700_000_000_u64.saturating_add(u64::from(esi)),
        },
        data: Bytes::from(data),
    }
}

fn mac_key(mode: u8) -> Option<[u8; 32]> {
    (mode % 2 == 1).then_some([0xA5; 32])
}

fn object_config(root: &Path, key: Option<[u8; 32]>) -> DurableObjectStoreConfig {
    let mut config = DurableObjectStoreConfig::new(root.to_path_buf());
    config.checkpoint_after_ops = 0;
    config.mac_key = key;
    config
}

fn symbol_config(root: &Path, key: Option<[u8; 32]>) -> DurableSymbolStoreConfig {
    let mut config = DurableSymbolStoreConfig::new(root.to_path_buf());
    config.checkpoint_after_ops = 0;
    config.mac_key = key;
    config
}

fn temp_base_name(snapshot_name: &str, last_seq: u64) -> String {
    format!("{snapshot_name}.tmp.{}.{}", std::process::id(), last_seq)
}

fn seed_temp_collisions(root: &Path, snapshot_name: &str, last_seq: u64, count: u8, bytes: &[u8]) {
    let base = temp_base_name(snapshot_name, last_seq);
    for suffix in 0..usize::from(count.min(4)) {
        let name = if suffix == 0 {
            base.clone()
        } else {
            format!("{base}.{suffix}")
        };
        let path = root.join(name);
        let contents = if bytes.is_empty() {
            b"stale-apfs-temp".as_slice()
        } else {
            &bytes[..bytes.len().min(64)]
        };
        let _ = fs::write(path, contents);
    }
}

fn target_path(root: &Path, fault: &FaultSpec, object: bool) -> PathBuf {
    let names = if object {
        [
            "objects.wal.jsonl",
            "objects.snapshot.json",
            "objects.snapshot.json.tmp.stale",
        ]
    } else {
        [
            "symbols.wal.jsonl",
            "symbols.snapshot.json",
            "symbols.snapshot.json.tmp.stale",
        ]
    };
    root.join(names[usize::from(fault.target % 3)])
}

fn apply_fault(root: &Path, fault: &FaultSpec, tail: &[u8], object: bool) {
    let path = target_path(root, fault, object);
    if fault.target % 3 == 2 {
        let contents = tail.get(..tail.len().min(MAX_TAIL_BYTES)).unwrap_or(tail);
        let _ = fs::write(path, contents);
        return;
    }

    let Ok(mut bytes) = fs::read(&path) else {
        return;
    };
    if bytes.is_empty() {
        return;
    }

    let offset = usize::try_from(fault.offset).unwrap_or(0) % bytes.len();
    let len = usize::from(fault.len)
        .max(1)
        .min(bytes.len().saturating_sub(offset).max(1));

    match fault.kind % 5 {
        0 => {}
        1 => {
            bytes.truncate(offset);
            let _ = fs::write(path, bytes);
        }
        2 => {
            let append = tail.get(..tail.len().min(MAX_TAIL_BYTES)).unwrap_or(tail);
            if let Ok(mut file) = OpenOptions::new().append(true).open(path) {
                let _ = file.write_all(append);
                let _ = file.sync_all();
            }
        }
        3 => {
            let end = offset.saturating_add(len).min(bytes.len());
            for byte in &mut bytes[offset..end] {
                *byte ^= fault.byte;
            }
            let _ = fs::write(path, bytes);
        }
        _ => {
            let page_start = (offset / PARTIAL_PAGE) * PARTIAL_PAGE;
            let end = page_start
                .saturating_add(len.min(PARTIAL_PAGE))
                .min(bytes.len());
            for byte in &mut bytes[page_start..end] {
                *byte = fault.byte;
            }
            let _ = fs::write(path, bytes);
        }
    }
}

fn recovered_object_ids(
    root: &Path,
    zone_id: &ZoneId,
    key: Option<[u8; 32]>,
) -> Option<Vec<ObjectId>> {
    let store = DurableObjectStore::open(object_config(root, key)).ok()?;
    block_on_sync(async { store.list_zone(zone_id).await }).ok()
}

fn assert_object_recovery_fixed_point(
    root: &Path,
    zone_id: &ZoneId,
    expected: &[ObjectId],
    key: Option<[u8; 32]>,
) {
    let Some(first) = recovered_object_ids(root, zone_id, key) else {
        return;
    };
    let expected_set = expected.iter().copied().collect::<BTreeSet<_>>();
    for id in &first {
        assert!(
            expected_set.contains(id),
            "writer-side WAL/snapshot fault recovered fabricated object id {id}"
        );
    }
    let second = recovered_object_ids(root, zone_id, key).expect("recovered object store reopens");
    assert_eq!(
        first, second,
        "object WAL truncation or snapshot recovery was not fixed-point"
    );
}

fn recovered_symbol_esis(
    root: &Path,
    object_id: ObjectId,
    key: Option<[u8; 32]>,
) -> Option<Vec<u32>> {
    let store = DurableSymbolStore::open(symbol_config(root, key)).ok()?;
    let mut esis = block_on_sync(async {
        store
            .get_all_symbols(&object_id)
            .await
            .into_iter()
            .map(|symbol| {
                assert_eq!(
                    symbol.meta.object_id, object_id,
                    "symbol recovery returned a symbol under the wrong object id"
                );
                assert_eq!(
                    symbol.data.len(),
                    64,
                    "symbol_map recovery admitted a partial-page symbol payload"
                );
                symbol.meta.esi
            })
            .collect::<Vec<_>>()
    })
    .ok()?;
    esis.sort_unstable();
    esis.dedup();
    Some(esis)
}

fn assert_symbol_recovery_fixed_point(
    root: &Path,
    object_id: ObjectId,
    expected_count: u32,
    key: Option<[u8; 32]>,
) {
    let Some(first) = recovered_symbol_esis(root, object_id, key) else {
        return;
    };
    for esi in &first {
        assert!(
            *esi < expected_count,
            "symbol_map recovery fabricated esi {esi} beyond written range {expected_count}"
        );
    }
    let second =
        recovered_symbol_esis(root, object_id, key).expect("recovered symbol store reopens");
    assert_eq!(
        first, second,
        "symbol WAL truncation or snapshot recovery was not fixed-point"
    );
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_INPUT_BYTES {
        return;
    }

    let mut unstructured = Unstructured::new(data);
    let Ok(input) = FuzzInput::arbitrary(&mut unstructured) else {
        return;
    };

    let Ok(dir) = TempDir::new() else {
        return;
    };
    let root = dir.path();
    let zone_id = zone(input.zone_choice);
    let key = mac_key(input.mac_mode);
    let object_count = usize::from(input.object_count % (MAX_OBJECTS as u8)).saturating_add(1);
    let symbol_count = u32::from(input.symbol_count % (MAX_SYMBOLS as u8)).saturating_add(1);

    let mut expected_objects = Vec::with_capacity(object_count);
    let first_object_id = object_id(input.object_seed, 0);

    let object_write = block_on_sync(async {
        let store = DurableObjectStore::open(object_config(root, key))?;
        for index in 0..object_count {
            let stored = object(input.object_seed, index, &zone_id, &input.body);
            expected_objects.push(stored.object_id);
            store.put(stored).await?;
        }
        if input.checkpoint_mode & 0b01 != 0 {
            seed_temp_collisions(
                root,
                "objects.snapshot.json",
                object_count as u64,
                input.stale_temp_collisions,
                &input.tail,
            );
            store.checkpoint().await?;
        }
        Ok::<(), fcp_store::ObjectStoreError>(())
    });
    if !matches!(object_write, Ok(Ok(()))) {
        return;
    }

    let symbol_write = block_on_sync(async {
        let store = DurableSymbolStore::open(symbol_config(root, key))?;
        let meta = symbol_meta(first_object_id, &zone_id, symbol_count);
        store.put_object_meta(meta.clone()).await?;
        for esi in 0..symbol_count {
            store
                .put_symbol(symbol(
                    &meta,
                    esi,
                    input.object_seed.wrapping_add(esi as u8),
                    &input.body,
                ))
                .await?;
        }
        if input.checkpoint_mode & 0b10 != 0 {
            let last_seq = u64::from(symbol_count).saturating_add(1);
            seed_temp_collisions(
                root,
                "symbols.snapshot.json",
                last_seq,
                input.stale_temp_collisions,
                &input.tail,
            );
            store.checkpoint()?;
        }
        Ok::<(), fcp_store::SymbolStoreError>(())
    });
    if !matches!(symbol_write, Ok(Ok(()))) {
        return;
    }

    apply_fault(root, &input.object_fault, &input.tail, true);
    apply_fault(root, &input.symbol_fault, &input.tail, false);

    assert_object_recovery_fixed_point(root, &zone_id, &expected_objects, key);
    assert_symbol_recovery_fixed_point(root, first_object_id, symbol_count, key);
});
