use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{Duration as ChronoDuration, Utc};
use fcp_core::{
    CONNECTOR_STATE_APPEND_OPERATION_ID, CONNECTOR_STATE_WRITE_CAPABILITY_ID,
    CapabilityConstraints, CapabilityToken, CapabilityVerifier, ConnectorId,
    ConnectorStateAppendOutcome, ConnectorStateChangeKind, ConnectorStateError,
    ConnectorStateObject, ConnectorStateRoot, ConnectorStateStore,
    ConnectorStateWriteAuthorization, InstanceId, ObjectHeader, ObjectId, ObjectIdKey, Provenance,
    Signature, ZoneId, connector_state_resource_uri,
};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_store::{
    FcpStoreConnectorStateStore, MemoryObjectStore, MemoryObjectStoreConfig, ObjectStore,
};
use futures_util::StreamExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn block_on<F>(future: F) -> F::Output
where
    F: Future,
{
    fcp_async_core::runtime::block_on_sync(future).expect("test runtime should start")
}

fn memory_object_store() -> Arc<dyn ObjectStore> {
    Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()))
}

fn object_id_key() -> ObjectIdKey {
    ObjectIdKey::from_bytes([0xA3; 32])
}

fn connector_id() -> ConnectorId {
    ConnectorId::from_static("slack:chat:v1")
}

fn zone_id() -> ZoneId {
    ZoneId::work()
}

fn connector_state_authorization() -> ConnectorStateWriteAuthorization {
    let connector_id = connector_id();
    let zone_id = zone_id();
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let constraints = CapabilityConstraints {
        resource_allow: vec![connector_state_resource_uri(&connector_id)],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor).unwrap();
    let now = Utc::now();
    let token = CapabilityToken::from_raw(
        CapabilityTokenBuilder::new()
            .capability_id(CONNECTOR_STATE_WRITE_CAPABILITY_ID)
            .zone_id(zone_id.as_str())
            .target_instance(instance_id.as_str())
            .principal("principal:test")
            .operations(&[CONNECTOR_STATE_APPEND_OPERATION_ID])
            .issuer("node:test")
            .validity(now, now + ChronoDuration::hours(1))
            .try_constraints_cbor(&constraints_cbor)
            .unwrap()
            .sign(&signing_key)
            .unwrap(),
    );
    let verifier = CapabilityVerifier::new(
        signing_key.verifying_key().to_bytes(),
        zone_id.clone(),
        instance_id,
    );

    ConnectorStateWriteAuthorization::verify_append_token(&verifier, token, &connector_id, &zone_id)
        .expect("connector-state write token should authorize append")
}

fn lease_id(seed: u8) -> ObjectId {
    ObjectId::from_bytes([seed; 32])
}

fn host_state_store(object_store: Arc<dyn ObjectStore>) -> FcpStoreConnectorStateStore {
    FcpStoreConnectorStateStore::new(object_store, object_id_key(), connector_id(), zone_id())
        .with_snapshot_every_entries(0)
        .with_snapshot_every_secs(0)
}

fn state_cbor(seq: u64) -> Vec<u8> {
    let seq_byte = u8::try_from(seq).expect("test sequence should fit in one CBOR byte");
    Vec::from([0xa1, 0x61, b'n', seq_byte])
}

fn state_header(seq: u64, lease: ObjectId) -> ObjectHeader {
    ObjectHeader {
        schema: FcpStoreConnectorStateStore::state_object_schema_id(),
        zone_id: zone_id(),
        created_at: 1_800_100_000 + seq,
        provenance: Provenance::new(zone_id()),
        refs: vec![lease],
        foreign_refs: Vec::new(),
        ttl_secs: None,
        placement: None,
    }
}

fn state(seq: u64, prev: Option<ObjectId>, lease: ObjectId) -> ConnectorStateObject {
    ConnectorStateObject {
        header: state_header(seq, lease),
        connector_id: connector_id(),
        instance_id: None,
        zone_id: zone_id(),
        prev,
        seq,
        state_cbor: state_cbor(seq),
        updated_at: 1_800_100_000 + seq,
        lease_seq: seq + 10,
        lease_object_id: lease,
        signature: Signature::zero(),
    }
}

fn append_committed(
    store: &FcpStoreConnectorStateStore,
    state_obj: ConnectorStateObject,
) -> Result<(ObjectId, ObjectId, u64), ConnectorStateError> {
    let connector_id = connector_id();
    let authorization = connector_state_authorization();
    match block_on(ConnectorStateStore::append_object(
        store,
        &connector_id,
        &authorization,
        state_obj,
    ))? {
        ConnectorStateAppendOutcome::Committed {
            object_id,
            root_object_id,
            seq,
            snapshot_object_id,
        } => {
            assert_eq!(snapshot_object_id, None);
            Ok((object_id, root_object_id, seq))
        }
        ConnectorStateAppendOutcome::Conflict {
            canonical_head,
            canonical_seq,
        } => panic!(
            "expected committed state object, got conflict at {canonical_head:?} seq {canonical_seq:?}"
        ),
    }
}

fn read_root(
    store: &FcpStoreConnectorStateStore,
) -> Result<ConnectorStateRoot, ConnectorStateError> {
    let connector_id = connector_id();
    block_on(ConnectorStateStore::read_root(store, &connector_id))?.ok_or_else(|| {
        ConnectorStateError::SnapshotUnavailable {
            connector_id,
            reason: "connector state root missing in test".to_string(),
        }
    })
}

#[test]
fn connector_state_subscribe_invalidates_second_host_handle() -> TestResult {
    let object_store = memory_object_store();
    let host_a = host_state_store(Arc::clone(&object_store));
    let host_b = host_state_store(Arc::clone(&object_store));
    let mut host_b_changes = block_on(ConnectorStateStore::subscribe_changes(
        &host_b,
        &connector_id(),
    ))?;

    let started = Instant::now();
    let (head_0, root_0, seq_0) = append_committed(&host_a, state(0, None, lease_id(1)))?;
    assert_eq!(seq_0, 0);

    let appended = block_on(host_b_changes.next())
        .expect("second host handle should observe object append")?;
    assert_eq!(appended.kind, ConnectorStateChangeKind::ObjectAppended);
    assert_eq!(appended.object_id, Some(head_0));
    assert_eq!(appended.seq, Some(0));

    let root =
        block_on(host_b_changes.next()).expect("second host handle should observe root update")?;
    assert_eq!(root.kind, ConnectorStateChangeKind::RootUpdated);
    assert_eq!(root.object_id, Some(root_0));
    assert_eq!(root.seq, Some(0));

    let propagation = started.elapsed();
    assert!(
        propagation < Duration::from_millis(100),
        "same-store connector state invalidation took {propagation:?}"
    );

    let host_b_root = read_root(&host_b)?;
    assert_eq!(host_b_root.head, Some(head_0));

    Ok(())
}
