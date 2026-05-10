//! Connector-state persistence on top of the FCPS object store.
//!
//! The store treats mesh objects as canonical connector state. Local files can
//! cache these objects, but this module is the content-addressed storage seam
//! that host and SDK code can share as the mesh-native path lands.

use std::sync::Arc;
use std::time::Instant;

use fcp_cbor::{CanonicalSerializer, SchemaId, SerializationError};
use fcp_prelude::{
    ConnectorId, ConnectorStateAppendOutcome, ConnectorStateChangeStream, ConnectorStateError,
    ConnectorStateModel, ConnectorStateObject, ConnectorStateRoot, ConnectorStateSnapshot,
    ConnectorStateStore, InstanceId, ObjectHeader, ObjectId, ObjectIdKey, RetentionClass,
    StorageMeta, StoredObject, ZoneId,
};
use semver::Version;
use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::{ObjectStore, ObjectStoreError};

/// Marker file name written by host-local connector-state cache directories.
///
/// The object store does not create cache directories, but keeping the marker
/// name here gives host adapters one canonical spelling when they expose the
/// cache-vs-canonical distinction to operators.
pub const CONNECTOR_STATE_CACHE_MARKER: &str = ".fcp-cache-only";

/// Tracing target for connector-state storage events.
pub const CONNECTOR_STATE_TRACING_TARGET: &str = "fcp.connector_state";
/// Structured event name emitted for connector-state reads.
pub const CONNECTOR_STATE_READ_EVENT: &str = "fcp.connector_state.read";
/// Structured event name emitted for connector-state writes.
pub const CONNECTOR_STATE_WRITE_EVENT: &str = "fcp.connector_state.write";
/// Structured event name emitted for connector-state snapshots.
pub const CONNECTOR_STATE_SNAPSHOT_EVENT: &str = "fcp.connector_state.snapshot";
/// Structured event name emitted for connector-state compaction.
pub const CONNECTOR_STATE_COMPACT_EVENT: &str = "fcp.connector_state.compact";
/// Structured event name reserved for host cache fall-through paths.
pub const CONNECTOR_STATE_FALL_THROUGH_EVENT: &str = "fcp.connector_state.fall_through";
/// Counter for connector-state writes by result.
pub const CONNECTOR_STATE_WRITES_TOTAL_METRIC: &str = "fcp_connector_state_writes_total";
/// Counter for host-local connector-state cache hits.
pub const CONNECTOR_STATE_CACHE_HITS_TOTAL_METRIC: &str = "fcp_connector_state_cache_hits_total";
/// Counter for cache misses falling through to canonical storage.
pub const CONNECTOR_STATE_FALL_THROUGH_TOTAL_METRIC: &str =
    "fcp_connector_state_fall_through_total";
/// Histogram for connector-state operation latency in seconds.
pub const CONNECTOR_STATE_LATENCY_SECONDS_METRIC: &str = "fcp_connector_state_latency_seconds";

/// Errors returned by [`FcpStoreConnectorStateStore`].
#[derive(Debug, Error)]
pub enum ConnectorStateStoreError {
    /// Object store operation failed.
    #[error("object store error: {0}")]
    ObjectStore(#[from] ObjectStoreError),

    /// Canonical serialization failed.
    #[error("serialization error: {0}")]
    Serialization(#[from] SerializationError),

    /// Stored object used an unexpected schema.
    #[error("unexpected schema for {kind}: expected {expected}, got {got}")]
    UnexpectedSchema {
        /// Object kind being decoded.
        kind: &'static str,
        /// Expected schema.
        expected: String,
        /// Actual schema.
        got: String,
    },

    /// Decoded state belongs to a different identity than this store.
    #[error("connector state identity mismatch for {field}: expected {expected}, got {got}")]
    IdentityMismatch {
        /// Field that mismatched.
        field: &'static str,
        /// Expected value.
        expected: String,
        /// Actual value.
        got: String,
    },

    /// State-object header does not mirror its storage envelope.
    #[error("state object header does not match stored envelope")]
    HeaderBodyMismatch,

    /// Stored object id does not match the keyed content derivation.
    #[error("content-id mismatch: claimed {claimed}, computed {computed}")]
    ContentIdMismatch {
        /// Claimed object id.
        claimed: ObjectId,
        /// Computed object id.
        computed: ObjectId,
    },

    /// A state object omitted the lease object from its header refs.
    #[error("connector state object missing lease reference {0}")]
    MissingLeaseReference(ObjectId),

    /// A state object used a sequence number that does not follow the head.
    #[error("connector state sequence mismatch: expected {expected}, got {got}")]
    SequenceMismatch {
        /// Expected next sequence number.
        expected: u64,
        /// Incoming sequence number.
        got: u64,
    },

    /// The root points at an object that cannot be loaded.
    #[error("connector state root references missing state object {0}")]
    MissingHead(ObjectId),

    /// Sequence increment overflowed.
    #[error("connector state sequence overflow at {0}")]
    SequenceOverflow(u64),
}

type Result<T> = std::result::Result<T, ConnectorStateStoreError>;

/// Connector-state store backed by an [`ObjectStore`].
#[derive(Clone)]
pub struct FcpStoreConnectorStateStore {
    object_store: Arc<dyn ObjectStore>,
    object_id_key: ObjectIdKey,
    connector_id: ConnectorId,
    zone_id: ZoneId,
    instance_id: Option<InstanceId>,
    state_model: ConnectorStateModel,
    retention: RetentionClass,
    snapshot_every_entries: u64,
}

impl FcpStoreConnectorStateStore {
    /// Create a connector-state store for one connector+zone identity.
    #[must_use]
    pub fn new(
        object_store: Arc<dyn ObjectStore>,
        object_id_key: ObjectIdKey,
        connector_id: ConnectorId,
        zone_id: ZoneId,
    ) -> Self {
        Self {
            object_store,
            object_id_key,
            connector_id,
            zone_id,
            instance_id: None,
            state_model: ConnectorStateModel::SingletonWriter,
            retention: RetentionClass::Pinned,
            snapshot_every_entries: 1_000,
        }
    }

    /// Scope the store to one connector instance.
    #[must_use]
    pub fn with_instance_id(mut self, instance_id: InstanceId) -> Self {
        self.instance_id = Some(instance_id);
        self
    }

    /// Configure the state model used when append creates or advances a root.
    #[must_use]
    pub const fn with_state_model(mut self, state_model: ConnectorStateModel) -> Self {
        self.state_model = state_model;
        self
    }

    /// Override retention for newly stored root/state/snapshot objects.
    #[must_use]
    pub const fn with_retention(mut self, retention: RetentionClass) -> Self {
        self.retention = retention;
        self
    }

    /// Emit a snapshot every N committed state objects. Zero disables automatic snapshots.
    #[must_use]
    pub const fn with_snapshot_every_entries(mut self, snapshot_every_entries: u64) -> Self {
        self.snapshot_every_entries = snapshot_every_entries;
        self
    }

    /// Schema used for canonical state-root objects.
    #[must_use]
    pub fn root_schema_id() -> SchemaId {
        SchemaId::new("fcp.connector_state", "state_root", Version::new(1, 0, 0))
    }

    /// Schema used for canonical state-chain objects.
    #[must_use]
    pub fn state_object_schema_id() -> SchemaId {
        SchemaId::new("fcp.connector_state", "state_object", Version::new(1, 0, 0))
    }

    /// Schema used for canonical state snapshots.
    #[must_use]
    pub fn snapshot_schema_id() -> SchemaId {
        SchemaId::new(
            "fcp.connector_state",
            "state_snapshot",
            Version::new(1, 0, 0),
        )
    }

    /// Return the latest state root for this connector, if present.
    ///
    /// # Errors
    /// Returns an error if a matching root object is malformed or fails
    /// content-id verification.
    pub async fn read_root(&self) -> Result<Option<(ObjectId, ConnectorStateRoot)>> {
        let started = Instant::now();
        let result = self.read_root_inner().await;
        let telemetry_result = match &result {
            Ok(Some(_)) => "hit",
            Ok(None) => "miss",
            Err(_) => "error",
        };
        self.record_operation_telemetry(
            CONNECTOR_STATE_READ_EVENT,
            "read",
            telemetry_result,
            started,
        );
        result
    }

    async fn read_root_inner(&self) -> Result<Option<(ObjectId, ConnectorStateRoot)>> {
        let mut best: Option<(ObjectId, ConnectorStateRoot)> = None;

        for object_id in self.object_store.list_zone(&self.zone_id).await {
            let stored = self.object_store.get(&object_id).await?;
            if stored.header.schema != Self::root_schema_id() {
                continue;
            }

            let root: ConnectorStateRoot =
                self.decode_stored(&stored, &Self::root_schema_id(), "connector state root")?;
            if !self.root_belongs_to_store(&root) {
                continue;
            }
            self.validate_root(&root)?;

            let replace = best.as_ref().is_none_or(|(best_id, best_root)| {
                root.header
                    .created_at
                    .cmp(&best_root.header.created_at)
                    .then(object_id.cmp(best_id))
                    .is_gt()
            });
            if replace {
                best = Some((object_id, root));
            }
        }

        Ok(best)
    }

    /// Store a state root and return its content-addressed object id.
    ///
    /// # Errors
    /// Returns an error when the root identity or schema does not match this store.
    pub async fn store_root(&self, root: ConnectorStateRoot) -> Result<ObjectId> {
        self.validate_root(&root)?;
        let stored = self.stored_object(&root.header, &root, self.retention)?;
        let object_id = stored.object_id;
        self.put_idempotent(stored).await?;
        Ok(object_id)
    }

    /// Append a state object if its prev pointer matches the canonical head.
    ///
    /// # Errors
    /// Returns an error when the incoming object is malformed or storage fails.
    pub async fn append_object(
        &self,
        state_obj: ConnectorStateObject,
    ) -> Result<ConnectorStateAppendOutcome> {
        let started = Instant::now();
        let result = self.append_object_inner(state_obj).await;
        let telemetry_result = match &result {
            Ok(ConnectorStateAppendOutcome::Committed { .. }) => "committed",
            Ok(ConnectorStateAppendOutcome::Conflict { .. }) => "conflict",
            Err(_) => "error",
        };
        fcp_telemetry::metrics::increment_counter(
            CONNECTOR_STATE_WRITES_TOTAL_METRIC,
            &[("result", telemetry_result)],
        );
        self.record_operation_telemetry(
            CONNECTOR_STATE_WRITE_EVENT,
            "write",
            telemetry_result,
            started,
        );
        result
    }

    async fn append_object_inner(
        &self,
        state_obj: ConnectorStateObject,
    ) -> Result<ConnectorStateAppendOutcome> {
        self.validate_incoming_state_object(&state_obj)?;

        let current = self.current_head().await?;
        let expected_prev = current.as_ref().map(|(object_id, _state)| *object_id);
        if state_obj.prev != expected_prev {
            return Ok(ConnectorStateAppendOutcome::Conflict {
                canonical_head: expected_prev,
                canonical_seq: current.as_ref().map(|(_object_id, state)| state.seq),
            });
        }

        let expected_seq = match current {
            Some((_object_id, state)) => state
                .seq
                .checked_add(1)
                .ok_or(ConnectorStateStoreError::SequenceOverflow(state.seq))?,
            None => 0,
        };
        if state_obj.seq != expected_seq {
            return Err(ConnectorStateStoreError::SequenceMismatch {
                expected: expected_seq,
                got: state_obj.seq,
            });
        }

        let object_id = self.store_state_object(state_obj.clone()).await?;
        let root = self.root_for_head(&state_obj, object_id);
        let root_object_id = self.store_root(root).await?;
        let snapshot_object_id = self.maybe_emit_snapshot(object_id, &state_obj).await?;

        Ok(ConnectorStateAppendOutcome::Committed {
            object_id,
            root_object_id,
            seq: state_obj.seq,
            snapshot_object_id,
        })
    }

    /// Read state objects in ascending sequence order.
    ///
    /// # Errors
    /// Returns an error if a state object for this connector is malformed.
    pub async fn read_chain(
        &self,
        after_seq: Option<u64>,
        limit: usize,
    ) -> Result<Vec<(ObjectId, ConnectorStateObject)>> {
        let started = Instant::now();
        let result = self.read_chain_inner(after_seq, limit).await;
        let telemetry_result = match &result {
            Ok(states) if states.is_empty() => "miss",
            Ok(_) => "hit",
            Err(_) => "error",
        };
        self.record_operation_telemetry(
            CONNECTOR_STATE_READ_EVENT,
            "read",
            telemetry_result,
            started,
        );
        result
    }

    async fn read_chain_inner(
        &self,
        after_seq: Option<u64>,
        limit: usize,
    ) -> Result<Vec<(ObjectId, ConnectorStateObject)>> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let mut states = Vec::new();
        for object_id in self.object_store.list_zone(&self.zone_id).await {
            let stored = self.object_store.get(&object_id).await?;
            if stored.header.schema != Self::state_object_schema_id() {
                continue;
            }

            let state = self.load_state_from_stored(object_id, &stored)?;
            if !self.state_belongs_to_store(&state) {
                continue;
            }
            if after_seq.is_some_and(|min_seq| state.seq <= min_seq) {
                continue;
            }
            states.push((object_id, state));
        }

        states.sort_by(|(left_id, left), (right_id, right)| {
            left.seq
                .cmp(&right.seq)
                .then(left.lease_seq.cmp(&right.lease_seq))
                .then(left_id.cmp(right_id))
        });
        states.truncate(limit);
        Ok(states)
    }

    /// Emit a snapshot for the current head, if any.
    ///
    /// # Errors
    /// Returns an error if the root/head is missing or storage fails.
    pub async fn snapshot_head(&self) -> Result<Option<ObjectId>> {
        let Some((head_id, head)) = self.current_head().await? else {
            return Ok(None);
        };
        self.emit_snapshot(head_id, &head).await.map(Some)
    }

    /// Return the latest snapshot for this connector, if any.
    ///
    /// # Errors
    /// Returns an error if a matching snapshot is malformed.
    pub async fn latest_snapshot(&self) -> Result<Option<(ObjectId, ConnectorStateSnapshot)>> {
        let mut best: Option<(ObjectId, ConnectorStateSnapshot)> = None;

        for object_id in self.object_store.list_zone(&self.zone_id).await {
            let stored = self.object_store.get(&object_id).await?;
            if stored.header.schema != Self::snapshot_schema_id() {
                continue;
            }

            let snapshot: ConnectorStateSnapshot = self.decode_stored(
                &stored,
                &Self::snapshot_schema_id(),
                "connector state snapshot",
            )?;
            if !self.snapshot_belongs_to_store(&snapshot) {
                continue;
            }
            self.validate_snapshot(&snapshot)?;

            let replace = best.as_ref().is_none_or(|(best_id, best_snapshot)| {
                snapshot
                    .covers_seq
                    .cmp(&best_snapshot.covers_seq)
                    .then(snapshot.snapshotted_at.cmp(&best_snapshot.snapshotted_at))
                    .then(object_id.cmp(best_id))
                    .is_gt()
            });
            if replace {
                best = Some((object_id, snapshot));
            }
        }

        Ok(best)
    }

    /// Mark state objects older than `before_seq` as ephemeral for later GC.
    ///
    /// This method intentionally does not delete objects; it only relaxes
    /// retention on non-head chain entries so the GC layer can make the final
    /// reachability decision under its own policy.
    ///
    /// # Errors
    /// Returns an error if state loading or retention updates fail.
    pub async fn compact(&self, before_seq: u64) -> Result<usize> {
        let started = Instant::now();
        let result = self.compact_inner(before_seq).await;
        let telemetry_result = if result.is_ok() { "ok" } else { "error" };
        self.record_operation_telemetry(
            CONNECTOR_STATE_COMPACT_EVENT,
            "compact",
            telemetry_result,
            started,
        );
        result
    }

    async fn compact_inner(&self, before_seq: u64) -> Result<usize> {
        let states = self.read_chain(None, usize::MAX).await?;
        let mut updated = 0;
        for (object_id, state) in states {
            if state.seq < before_seq {
                self.object_store
                    .set_retention(&object_id, RetentionClass::Ephemeral)
                    .await?;
                updated += 1;
            }
        }
        Ok(updated)
    }

    async fn current_head(&self) -> Result<Option<(ObjectId, ConnectorStateObject)>> {
        let Some((_root_id, root)) = self.read_root().await? else {
            return Ok(None);
        };
        let Some(head_id) = root.head else {
            return Ok(None);
        };
        self.load_state_object(&head_id).await.map(Some)
    }

    async fn load_state_object(
        &self,
        object_id: &ObjectId,
    ) -> Result<(ObjectId, ConnectorStateObject)> {
        let stored = self
            .object_store
            .get(object_id)
            .await
            .map_err(|err| match err {
                ObjectStoreError::NotFound(_) => ConnectorStateStoreError::MissingHead(*object_id),
                other => ConnectorStateStoreError::ObjectStore(other),
            })?;
        let state = self.load_state_from_stored(*object_id, &stored)?;
        if !self.state_belongs_to_store(&state) {
            return Err(ConnectorStateStoreError::IdentityMismatch {
                field: "connector_id",
                expected: self.connector_id.to_string(),
                got: state.connector_id.to_string(),
            });
        }
        Ok((*object_id, state))
    }

    fn load_state_from_stored(
        &self,
        object_id: ObjectId,
        stored: &StoredObject,
    ) -> Result<ConnectorStateObject> {
        let state: ConnectorStateObject = self.decode_stored(
            stored,
            &Self::state_object_schema_id(),
            "connector state object",
        )?;
        self.validate_stored_state_object(object_id, stored, &state)?;
        Ok(state)
    }

    async fn store_state_object(&self, state_obj: ConnectorStateObject) -> Result<ObjectId> {
        let stored = self.stored_object(&state_obj.header, &state_obj, self.retention)?;
        let object_id = stored.object_id;
        self.put_idempotent(stored).await?;
        Ok(object_id)
    }

    async fn maybe_emit_snapshot(
        &self,
        object_id: ObjectId,
        state_obj: &ConnectorStateObject,
    ) -> Result<Option<ObjectId>> {
        if self.snapshot_every_entries == 0 {
            return Ok(None);
        }
        if (state_obj.seq + 1) % self.snapshot_every_entries != 0 {
            return Ok(None);
        }
        self.emit_snapshot(object_id, state_obj).await.map(Some)
    }

    async fn emit_snapshot(
        &self,
        covers_head: ObjectId,
        state_obj: &ConnectorStateObject,
    ) -> Result<ObjectId> {
        let started = Instant::now();
        let result = self.emit_snapshot_inner(covers_head, state_obj).await;
        let telemetry_result = if result.is_ok() { "emitted" } else { "error" };
        self.record_operation_telemetry(
            CONNECTOR_STATE_SNAPSHOT_EVENT,
            "snapshot",
            telemetry_result,
            started,
        );
        result
    }

    async fn emit_snapshot_inner(
        &self,
        covers_head: ObjectId,
        state_obj: &ConnectorStateObject,
    ) -> Result<ObjectId> {
        let mut header = self.derived_header(
            Self::snapshot_schema_id(),
            state_obj.header.created_at,
            state_obj.header.provenance.clone(),
        );
        header.refs.push(covers_head);
        header.placement.clone_from(&state_obj.header.placement);

        let snapshot = ConnectorStateSnapshot {
            header,
            connector_id: self.connector_id.clone(),
            instance_id: self.instance_id.clone(),
            zone_id: self.zone_id.clone(),
            covers_head,
            covers_seq: state_obj.seq,
            state_cbor: state_obj.state_cbor.clone(),
            snapshotted_at: state_obj.updated_at,
            signature: state_obj.signature,
        };

        self.validate_snapshot(&snapshot)?;
        let stored = self.stored_object(&snapshot.header, &snapshot, self.retention)?;
        let object_id = stored.object_id;
        self.put_idempotent(stored).await?;
        Ok(object_id)
    }

    async fn put_idempotent(&self, stored: StoredObject) -> Result<()> {
        match self.object_store.put(stored).await {
            Ok(()) | Err(ObjectStoreError::AlreadyExists(_)) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    fn stored_object<T: Serialize>(
        &self,
        header: &ObjectHeader,
        value: &T,
        retention: RetentionClass,
    ) -> Result<StoredObject> {
        let body = CanonicalSerializer::serialize(value, &header.schema)?;
        let object_id = StoredObject::derive_id(header, &body, &self.object_id_key)?;
        Ok(StoredObject {
            object_id,
            header: header.clone(),
            body,
            storage: StorageMeta { retention },
        })
    }

    fn decode_stored<T: DeserializeOwned + Serialize>(
        &self,
        stored: &StoredObject,
        expected_schema: &SchemaId,
        kind: &'static str,
    ) -> Result<T> {
        if stored.header.schema != *expected_schema {
            return Err(ConnectorStateStoreError::UnexpectedSchema {
                kind,
                expected: format!("{expected_schema:?}"),
                got: format!("{:?}", stored.header.schema),
            });
        }

        let computed = StoredObject::derive_id(&stored.header, &stored.body, &self.object_id_key)?;
        if computed != stored.object_id {
            return Err(ConnectorStateStoreError::ContentIdMismatch {
                claimed: stored.object_id,
                computed,
            });
        }

        Ok(CanonicalSerializer::deserialize(
            &stored.body,
            expected_schema,
        )?)
    }

    fn validate_root(&self, root: &ConnectorStateRoot) -> Result<()> {
        Self::expect_schema(
            "connector state root",
            &root.header.schema,
            &Self::root_schema_id(),
        )?;
        self.expect_connector(&root.connector_id)?;
        self.expect_zone("root.zone_id", &root.zone_id)?;
        self.expect_zone("root.header.zone_id", &root.header.zone_id)?;
        self.expect_instance(root.instance_id.as_ref())?;
        if let Some(head) = root.head
            && !root.header.refs.contains(&head)
        {
            return Err(ConnectorStateStoreError::MissingHead(head));
        }
        Ok(())
    }

    fn validate_snapshot(&self, snapshot: &ConnectorStateSnapshot) -> Result<()> {
        Self::expect_schema(
            "connector state snapshot",
            &snapshot.header.schema,
            &Self::snapshot_schema_id(),
        )?;
        self.expect_connector(&snapshot.connector_id)?;
        self.expect_zone("snapshot.zone_id", &snapshot.zone_id)?;
        self.expect_zone("snapshot.header.zone_id", &snapshot.header.zone_id)?;
        self.expect_instance(snapshot.instance_id.as_ref())?;
        if !snapshot.header.refs.contains(&snapshot.covers_head) {
            return Err(ConnectorStateStoreError::MissingHead(snapshot.covers_head));
        }
        Ok(())
    }

    fn validate_incoming_state_object(&self, state: &ConnectorStateObject) -> Result<()> {
        Self::expect_schema(
            "connector state object",
            &state.header.schema,
            &Self::state_object_schema_id(),
        )?;
        self.expect_connector(&state.connector_id)?;
        self.expect_zone("state.zone_id", &state.zone_id)?;
        self.expect_zone("state.header.zone_id", &state.header.zone_id)?;
        self.expect_instance(state.instance_id.as_ref())?;
        if !state.header.refs.contains(&state.lease_object_id) {
            return Err(ConnectorStateStoreError::MissingLeaseReference(
                state.lease_object_id,
            ));
        }
        Ok(())
    }

    fn validate_stored_state_object(
        &self,
        object_id: ObjectId,
        stored: &StoredObject,
        state: &ConnectorStateObject,
    ) -> Result<()> {
        self.validate_incoming_state_object(state)?;
        if !headers_match(&stored.header, &state.header)? {
            return Err(ConnectorStateStoreError::HeaderBodyMismatch);
        }
        let computed = StoredObject::derive_id(&stored.header, &stored.body, &self.object_id_key)?;
        if computed != object_id {
            return Err(ConnectorStateStoreError::ContentIdMismatch {
                claimed: object_id,
                computed,
            });
        }
        Ok(())
    }

    fn root_belongs_to_store(&self, root: &ConnectorStateRoot) -> bool {
        root.connector_id == self.connector_id
            && root.zone_id == self.zone_id
            && root.instance_id == self.instance_id
    }

    fn state_belongs_to_store(&self, state: &ConnectorStateObject) -> bool {
        state.connector_id == self.connector_id
            && state.zone_id == self.zone_id
            && state.instance_id == self.instance_id
    }

    fn snapshot_belongs_to_store(&self, snapshot: &ConnectorStateSnapshot) -> bool {
        snapshot.connector_id == self.connector_id
            && snapshot.zone_id == self.zone_id
            && snapshot.instance_id == self.instance_id
    }

    fn root_for_head(
        &self,
        state_obj: &ConnectorStateObject,
        head: ObjectId,
    ) -> ConnectorStateRoot {
        let mut header = self.derived_header(
            Self::root_schema_id(),
            state_obj.header.created_at,
            state_obj.header.provenance.clone(),
        );
        header.refs.push(head);
        header.placement.clone_from(&state_obj.header.placement);

        ConnectorStateRoot {
            header,
            connector_id: self.connector_id.clone(),
            instance_id: self.instance_id.clone(),
            zone_id: self.zone_id.clone(),
            model: self.state_model.clone(),
            head: Some(head),
            state_schema_version: 1,
        }
    }

    fn derived_header(
        &self,
        schema: SchemaId,
        created_at: u64,
        provenance: fcp_prelude::Provenance,
    ) -> ObjectHeader {
        ObjectHeader {
            schema,
            zone_id: self.zone_id.clone(),
            created_at,
            provenance,
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        }
    }

    fn expect_schema(kind: &'static str, got: &SchemaId, expected: &SchemaId) -> Result<()> {
        if got == expected {
            return Ok(());
        }
        Err(ConnectorStateStoreError::UnexpectedSchema {
            kind,
            expected: format!("{expected:?}"),
            got: format!("{got:?}"),
        })
    }

    fn expect_connector(&self, got: &ConnectorId) -> Result<()> {
        if got == &self.connector_id {
            return Ok(());
        }
        Err(ConnectorStateStoreError::IdentityMismatch {
            field: "connector_id",
            expected: self.connector_id.to_string(),
            got: got.to_string(),
        })
    }

    fn expect_zone(&self, field: &'static str, got: &ZoneId) -> Result<()> {
        if got == &self.zone_id {
            return Ok(());
        }
        Err(ConnectorStateStoreError::IdentityMismatch {
            field,
            expected: self.zone_id.to_string(),
            got: got.to_string(),
        })
    }

    fn expect_instance(&self, got: Option<&InstanceId>) -> Result<()> {
        if got == self.instance_id.as_ref() {
            return Ok(());
        }
        Err(ConnectorStateStoreError::IdentityMismatch {
            field: "instance_id",
            expected: self
                .instance_id
                .as_ref()
                .map_or_else(|| "<none>".to_string(), ToString::to_string),
            got: got.map_or_else(|| "<none>".to_string(), ToString::to_string),
        })
    }

    fn ensure_requested_connector(
        &self,
        connector_id: &ConnectorId,
    ) -> std::result::Result<(), ConnectorStateError> {
        if connector_id == &self.connector_id {
            return Ok(());
        }
        Err(ConnectorStateError::MalformedState {
            connector_id: connector_id.clone(),
            reason: format!(
                "requested connector_id does not match store connector_id {}",
                self.connector_id
            ),
        })
    }

    fn record_operation_telemetry(
        &self,
        event_type: &'static str,
        operation: &'static str,
        result: &'static str,
        started: Instant,
    ) {
        let latency_seconds = started.elapsed().as_secs_f64();
        fcp_telemetry::metrics::record_histogram(
            CONNECTOR_STATE_LATENCY_SECONDS_METRIC,
            latency_seconds,
            &[("operation", operation), ("result", result)],
        );
        tracing::info!(
            target: CONNECTOR_STATE_TRACING_TARGET,
            event_type,
            connector_id = %self.connector_id,
            zone_id = %self.zone_id,
            operation,
            result,
            latency_seconds,
            metric_name = CONNECTOR_STATE_LATENCY_SECONDS_METRIC,
        );
    }

    fn to_connector_state_error(&self, err: ConnectorStateStoreError) -> ConnectorStateError {
        match err {
            ConnectorStateStoreError::ObjectStore(err) => ConnectorStateError::StorageUnavailable {
                connector_id: self.connector_id.clone(),
                reason: err.to_string(),
            },
            ConnectorStateStoreError::MissingHead(head) => {
                ConnectorStateError::SnapshotUnavailable {
                    connector_id: self.connector_id.clone(),
                    reason: format!("root references missing state object {head}"),
                }
            }
            ConnectorStateStoreError::UnexpectedSchema { .. }
            | ConnectorStateStoreError::IdentityMismatch { .. }
            | ConnectorStateStoreError::HeaderBodyMismatch
            | ConnectorStateStoreError::ContentIdMismatch { .. }
            | ConnectorStateStoreError::MissingLeaseReference(_)
            | ConnectorStateStoreError::SequenceMismatch { .. }
            | ConnectorStateStoreError::SequenceOverflow(_)
            | ConnectorStateStoreError::Serialization(_) => ConnectorStateError::MalformedState {
                connector_id: self.connector_id.clone(),
                reason: err.to_string(),
            },
        }
    }
}

#[async_trait::async_trait]
impl ConnectorStateStore for FcpStoreConnectorStateStore {
    async fn read_root(
        &self,
        connector_id: &ConnectorId,
    ) -> std::result::Result<Option<ConnectorStateRoot>, ConnectorStateError> {
        self.ensure_requested_connector(connector_id)?;
        Self::read_root(self)
            .await
            .map(|root| root.map(|(_object_id, root)| root))
            .map_err(|err| self.to_connector_state_error(err))
    }

    async fn append_object(
        &self,
        connector_id: &ConnectorId,
        object: ConnectorStateObject,
    ) -> std::result::Result<ConnectorStateAppendOutcome, ConnectorStateError> {
        self.ensure_requested_connector(connector_id)?;
        Self::append_object(self, object)
            .await
            .map_err(|err| self.to_connector_state_error(err))
    }

    async fn read_chain(
        &self,
        connector_id: &ConnectorId,
        after_seq: Option<u64>,
        limit: usize,
    ) -> std::result::Result<Vec<ConnectorStateObject>, ConnectorStateError> {
        self.ensure_requested_connector(connector_id)?;
        Self::read_chain(self, after_seq, limit)
            .await
            .map(|states| {
                states
                    .into_iter()
                    .map(|(_object_id, state)| state)
                    .collect()
            })
            .map_err(|err| self.to_connector_state_error(err))
    }

    async fn snapshot(
        &self,
        connector_id: &ConnectorId,
    ) -> std::result::Result<ConnectorStateSnapshot, ConnectorStateError> {
        self.ensure_requested_connector(connector_id)?;
        let snapshot_id = Self::snapshot_head(self)
            .await
            .map_err(|err| self.to_connector_state_error(err))?
            .ok_or_else(|| ConnectorStateError::SnapshotUnavailable {
                connector_id: connector_id.clone(),
                reason: "no connector state head exists".to_string(),
            })?;
        let Some((latest_id, snapshot)) = Self::latest_snapshot(self)
            .await
            .map_err(|err| self.to_connector_state_error(err))?
        else {
            return Err(ConnectorStateError::SnapshotUnavailable {
                connector_id: connector_id.clone(),
                reason: "snapshot was emitted but could not be reloaded".to_string(),
            });
        };
        if latest_id != snapshot_id {
            return Err(ConnectorStateError::SnapshotUnavailable {
                connector_id: connector_id.clone(),
                reason: format!("latest snapshot {latest_id} did not match emitted {snapshot_id}"),
            });
        }
        Ok(snapshot)
    }

    async fn compact(
        &self,
        connector_id: &ConnectorId,
        before_seq: u64,
    ) -> std::result::Result<usize, ConnectorStateError> {
        self.ensure_requested_connector(connector_id)?;
        Self::compact(self, before_seq)
            .await
            .map_err(|err| self.to_connector_state_error(err))
    }

    async fn subscribe_changes(
        &self,
        connector_id: &ConnectorId,
    ) -> std::result::Result<ConnectorStateChangeStream, ConnectorStateError> {
        self.ensure_requested_connector(connector_id)?;
        Err(ConnectorStateError::SubscribeUnavailable {
            connector_id: connector_id.clone(),
            reason: "mesh gossip connector-state change stream is not wired in fcp-store"
                .to_string(),
        })
    }
}

fn headers_match(left: &ObjectHeader, right: &ObjectHeader) -> Result<bool> {
    Ok(fcp_cbor::to_canonical_cbor(left)? == fcp_cbor::to_canonical_cbor(right)?)
}

#[cfg(test)]
mod tests {
    use std::panic::{self, AssertUnwindSafe};

    use fcp_prelude::{Provenance, Signature};

    use super::*;
    use crate::{MemoryObjectStore, MemoryObjectStoreConfig};

    fn run_async<F, T>(future: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        fcp_async_core::runtime::block_on_sync(future).expect("runtime")
    }

    fn store() -> Arc<MemoryObjectStore> {
        Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()))
    }

    fn object_id_key() -> ObjectIdKey {
        ObjectIdKey::from_bytes([42; 32])
    }

    fn connector_id() -> ConnectorId {
        ConnectorId::from_static("slack:chat:v1")
    }

    fn other_connector_id() -> ConnectorId {
        ConnectorId::from_static("github:request_response:v1")
    }

    fn zone_id() -> ZoneId {
        ZoneId::work()
    }

    fn other_zone_id() -> ZoneId {
        ZoneId::private()
    }

    fn lease_id(seed: u8) -> ObjectId {
        ObjectId::from_bytes([seed; 32])
    }

    fn test_store(object_store: Arc<dyn ObjectStore>) -> FcpStoreConnectorStateStore {
        FcpStoreConnectorStateStore::new(object_store, object_id_key(), connector_id(), zone_id())
    }

    fn header(schema: SchemaId, created_at: u64, lease: Option<ObjectId>) -> ObjectHeader {
        ObjectHeader {
            schema,
            zone_id: zone_id(),
            created_at,
            provenance: Provenance::new(zone_id()),
            refs: lease.into_iter().collect(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        }
    }

    fn state(seq: u64, prev: Option<ObjectId>, lease: ObjectId) -> ConnectorStateObject {
        ConnectorStateObject {
            header: header(
                FcpStoreConnectorStateStore::state_object_schema_id(),
                1_700_000_000 + seq,
                Some(lease),
            ),
            connector_id: connector_id(),
            instance_id: None,
            zone_id: zone_id(),
            prev,
            seq,
            state_cbor: vec![0xa1, 0x61, b'n', seq as u8],
            updated_at: 1_700_000_000 + seq,
            lease_seq: seq + 10,
            lease_object_id: lease,
            signature: Signature::zero(),
        }
    }

    fn root_with_head(head: Option<ObjectId>, created_at: u64) -> ConnectorStateRoot {
        let mut root_header = header(
            FcpStoreConnectorStateStore::root_schema_id(),
            created_at,
            None,
        );
        if let Some(head) = head {
            root_header.refs.push(head);
        }
        ConnectorStateRoot {
            header: root_header,
            connector_id: connector_id(),
            instance_id: None,
            zone_id: zone_id(),
            model: ConnectorStateModel::SingletonWriter,
            head,
            state_schema_version: 1,
        }
    }

    fn append_ok(
        state_store: &FcpStoreConnectorStateStore,
        state_obj: ConnectorStateObject,
    ) -> (ObjectId, Option<ObjectId>) {
        let outcome = run_async(state_store.append_object(state_obj)).unwrap();
        match outcome {
            ConnectorStateAppendOutcome::Committed {
                object_id,
                snapshot_object_id,
                ..
            } => (object_id, snapshot_object_id),
            ConnectorStateAppendOutcome::Conflict { .. } => {
                assert!(false, "unexpected conflict");
                (ObjectId::from_bytes([0; 32]), None)
            }
        }
    }

    fn catches_unwind<F: FnOnce() + panic::UnwindSafe>(f: F) {
        let result = panic::catch_unwind(AssertUnwindSafe(f));
        assert!(result.is_err());
    }

    #[test]
    fn schema_ids_are_stable() {
        assert_eq!(
            FcpStoreConnectorStateStore::root_schema_id(),
            SchemaId::new("fcp.connector_state", "state_root", Version::new(1, 0, 0))
        );
        assert_eq!(
            FcpStoreConnectorStateStore::state_object_schema_id(),
            SchemaId::new("fcp.connector_state", "state_object", Version::new(1, 0, 0))
        );
        assert_eq!(
            FcpStoreConnectorStateStore::snapshot_schema_id(),
            SchemaId::new(
                "fcp.connector_state",
                "state_snapshot",
                Version::new(1, 0, 0)
            )
        );
    }

    #[test]
    fn cache_marker_name_is_canonical() {
        assert_eq!(CONNECTOR_STATE_CACHE_MARKER, ".fcp-cache-only");
    }

    #[test]
    fn telemetry_contract_names_match_connector_state_acceptance() {
        assert_eq!(CONNECTOR_STATE_READ_EVENT, "fcp.connector_state.read");
        assert_eq!(CONNECTOR_STATE_WRITE_EVENT, "fcp.connector_state.write");
        assert_eq!(
            CONNECTOR_STATE_SNAPSHOT_EVENT,
            "fcp.connector_state.snapshot"
        );
        assert_eq!(CONNECTOR_STATE_COMPACT_EVENT, "fcp.connector_state.compact");
        assert_eq!(
            CONNECTOR_STATE_FALL_THROUGH_EVENT,
            "fcp.connector_state.fall_through"
        );
        assert_eq!(
            CONNECTOR_STATE_WRITES_TOTAL_METRIC,
            "fcp_connector_state_writes_total"
        );
        assert_eq!(
            CONNECTOR_STATE_CACHE_HITS_TOTAL_METRIC,
            "fcp_connector_state_cache_hits_total"
        );
        assert_eq!(
            CONNECTOR_STATE_FALL_THROUGH_TOTAL_METRIC,
            "fcp_connector_state_fall_through_total"
        );
        assert_eq!(
            CONNECTOR_STATE_LATENCY_SECONDS_METRIC,
            "fcp_connector_state_latency_seconds"
        );
    }

    #[test]
    fn read_root_empty_store_returns_none() {
        let state_store = test_store(store());
        assert!(run_async(state_store.read_root()).unwrap().is_none());
    }

    #[test]
    fn store_root_roundtrips() {
        let state_store = test_store(store());
        let root = root_with_head(None, 11);
        let root_id = run_async(state_store.store_root(root)).unwrap();
        let loaded = run_async(state_store.read_root()).unwrap().unwrap();
        assert_eq!(loaded.0, root_id);
        assert_eq!(loaded.1.head, None);
    }

    #[test]
    fn storing_same_root_is_idempotent() {
        let state_store = test_store(store());
        let root = root_with_head(None, 11);
        let first = run_async(state_store.store_root(root.clone())).unwrap();
        let second = run_async(state_store.store_root(root)).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn append_genesis_commits_state_and_root() {
        let object_store = store();
        let state_store = test_store(object_store);
        let outcome = run_async(state_store.append_object(state(0, None, lease_id(1)))).unwrap();
        match outcome {
            ConnectorStateAppendOutcome::Committed { seq, .. } => assert_eq!(seq, 0),
            ConnectorStateAppendOutcome::Conflict { .. } => catches_unwind(|| {}),
        }
        let root = run_async(state_store.read_root()).unwrap().unwrap().1;
        assert!(root.head.is_some());
    }

    #[test]
    fn read_chain_returns_genesis() {
        let state_store = test_store(store());
        let (head, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        let chain = run_async(state_store.read_chain(None, 10)).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].0, head);
        assert_eq!(chain[0].1.seq, 0);
    }

    #[test]
    fn append_second_object_links_to_previous_head() {
        let state_store = test_store(store());
        let (head0, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        let (head1, _) = append_ok(&state_store, state(1, Some(head0), lease_id(2)));
        let root = run_async(state_store.read_root()).unwrap().unwrap().1;
        assert_eq!(root.head, Some(head1));
    }

    #[test]
    fn append_rejects_wrong_prev_as_conflict() {
        let state_store = test_store(store());
        append_ok(&state_store, state(0, None, lease_id(1)));
        let wrong_prev = ObjectId::from_bytes([99; 32]);
        let outcome =
            run_async(state_store.append_object(state(1, Some(wrong_prev), lease_id(2)))).unwrap();
        match outcome {
            ConnectorStateAppendOutcome::Conflict {
                canonical_head,
                canonical_seq,
            } => {
                assert!(canonical_head.is_some());
                assert_eq!(canonical_seq, Some(0));
            }
            ConnectorStateAppendOutcome::Committed { .. } => {
                assert!(false, "expected conflict");
            }
        }
    }

    #[test]
    fn append_rejects_wrong_sequence() {
        let state_store = test_store(store());
        let (head0, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        let err =
            run_async(state_store.append_object(state(3, Some(head0), lease_id(2)))).unwrap_err();
        assert!(matches!(
            err,
            ConnectorStateStoreError::SequenceMismatch {
                expected: 1,
                got: 3
            }
        ));
    }

    #[test]
    fn append_rejects_wrong_connector() {
        let state_store = test_store(store());
        let mut incoming = state(0, None, lease_id(1));
        incoming.connector_id = other_connector_id();
        let err = run_async(state_store.append_object(incoming)).unwrap_err();
        assert!(matches!(
            err,
            ConnectorStateStoreError::IdentityMismatch {
                field: "connector_id",
                ..
            }
        ));
    }

    #[test]
    fn append_rejects_wrong_zone() {
        let state_store = test_store(store());
        let mut incoming = state(0, None, lease_id(1));
        incoming.zone_id = other_zone_id();
        let err = run_async(state_store.append_object(incoming)).unwrap_err();
        assert!(matches!(
            err,
            ConnectorStateStoreError::IdentityMismatch {
                field: "state.zone_id",
                ..
            }
        ));
    }

    #[test]
    fn append_rejects_wrong_schema() {
        let state_store = test_store(store());
        let mut incoming = state(0, None, lease_id(1));
        incoming.header.schema = FcpStoreConnectorStateStore::root_schema_id();
        let err = run_async(state_store.append_object(incoming)).unwrap_err();
        assert!(matches!(
            err,
            ConnectorStateStoreError::UnexpectedSchema {
                kind: "connector state object",
                ..
            }
        ));
    }

    #[test]
    fn append_rejects_missing_lease_ref() {
        let state_store = test_store(store());
        let mut incoming = state(0, None, lease_id(1));
        incoming.header.refs.clear();
        let err = run_async(state_store.append_object(incoming)).unwrap_err();
        assert!(matches!(
            err,
            ConnectorStateStoreError::MissingLeaseReference(_)
        ));
    }

    #[test]
    fn read_chain_sorts_by_sequence() {
        let state_store = test_store(store());
        let (head0, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        let (head1, _) = append_ok(&state_store, state(1, Some(head0), lease_id(2)));
        let (head2, _) = append_ok(&state_store, state(2, Some(head1), lease_id(3)));
        let chain = run_async(state_store.read_chain(None, 10)).unwrap();
        assert_eq!(
            chain.iter().map(|(_id, s)| s.seq).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert_eq!(chain[2].0, head2);
    }

    #[test]
    fn read_chain_after_seq_filters_inclusive_boundary() {
        let state_store = test_store(store());
        let (head0, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        let (head1, _) = append_ok(&state_store, state(1, Some(head0), lease_id(2)));
        append_ok(&state_store, state(2, Some(head1), lease_id(3)));
        let chain = run_async(state_store.read_chain(Some(1), 10)).unwrap();
        assert_eq!(
            chain.iter().map(|(_id, s)| s.seq).collect::<Vec<_>>(),
            vec![2]
        );
    }

    #[test]
    fn read_chain_zero_limit_returns_empty() {
        let state_store = test_store(store());
        append_ok(&state_store, state(0, None, lease_id(1)));
        assert!(
            run_async(state_store.read_chain(None, 0))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn read_chain_limit_truncates() {
        let state_store = test_store(store());
        let (head0, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        let (head1, _) = append_ok(&state_store, state(1, Some(head0), lease_id(2)));
        append_ok(&state_store, state(2, Some(head1), lease_id(3)));
        let chain = run_async(state_store.read_chain(None, 2)).unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[1].1.seq, 1);
    }

    #[test]
    fn instance_scoped_store_ignores_other_instance_root() {
        let object_store = store();
        let instance = InstanceId::new();
        let scoped = test_store(object_store.clone()).with_instance_id(instance.clone());
        let unscoped = test_store(object_store);
        append_ok(&unscoped, state(0, None, lease_id(1)));
        assert!(run_async(scoped.read_root()).unwrap().is_none());
        let mut scoped_state = state(0, None, lease_id(2));
        scoped_state.instance_id = Some(instance);
        append_ok(&scoped, scoped_state);
        assert!(run_async(scoped.read_root()).unwrap().is_some());
    }

    #[test]
    fn retention_override_applies_to_state_object() {
        let object_store = store();
        let state_store = test_store(object_store.clone())
            .with_retention(RetentionClass::Lease { expires_at: 77 });
        let (head, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        let meta = run_async(object_store.get_storage_meta(&head)).unwrap();
        assert_eq!(meta.retention, RetentionClass::Lease { expires_at: 77 });
    }

    #[test]
    fn compact_marks_older_states_ephemeral() {
        let object_store = store();
        let state_store = test_store(object_store.clone());
        let (head0, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        let (head1, _) = append_ok(&state_store, state(1, Some(head0), lease_id(2)));
        let count = run_async(state_store.compact(1)).unwrap();
        assert_eq!(count, 1);
        let old_meta = run_async(object_store.get_storage_meta(&head0)).unwrap();
        let new_meta = run_async(object_store.get_storage_meta(&head1)).unwrap();
        assert_eq!(old_meta.retention, RetentionClass::Ephemeral);
        assert_eq!(new_meta.retention, RetentionClass::Pinned);
    }

    #[test]
    fn compact_boundary_does_not_mark_equal_sequence() {
        let object_store = store();
        let state_store = test_store(object_store.clone());
        let (head0, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        let count = run_async(state_store.compact(0)).unwrap();
        assert_eq!(count, 0);
        let meta = run_async(object_store.get_storage_meta(&head0)).unwrap();
        assert_eq!(meta.retention, RetentionClass::Pinned);
    }

    #[test]
    fn latest_snapshot_empty_store_returns_none() {
        let state_store = test_store(store());
        assert!(run_async(state_store.latest_snapshot()).unwrap().is_none());
    }

    #[test]
    fn snapshot_head_empty_store_returns_none() {
        let state_store = test_store(store());
        assert!(run_async(state_store.snapshot_head()).unwrap().is_none());
    }

    #[test]
    fn automatic_snapshot_emits_on_configured_interval() {
        let state_store = test_store(store()).with_snapshot_every_entries(2);
        let (head0, first_snapshot) = append_ok(&state_store, state(0, None, lease_id(1)));
        let (_head1, second_snapshot) = append_ok(&state_store, state(1, Some(head0), lease_id(2)));
        assert!(first_snapshot.is_none());
        assert!(second_snapshot.is_some());
        let latest = run_async(state_store.latest_snapshot()).unwrap().unwrap();
        assert_eq!(latest.1.covers_seq, 1);
    }

    #[test]
    fn snapshot_head_uses_current_head() {
        let state_store = test_store(store()).with_snapshot_every_entries(0);
        let (head0, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        let snapshot_id = run_async(state_store.snapshot_head()).unwrap().unwrap();
        let latest = run_async(state_store.latest_snapshot()).unwrap().unwrap();
        assert_eq!(latest.0, snapshot_id);
        assert_eq!(latest.1.covers_head, head0);
    }

    #[test]
    fn snapshot_latest_prefers_highest_sequence() {
        let state_store = test_store(store()).with_snapshot_every_entries(1);
        let (head0, _) = append_ok(&state_store, state(0, None, lease_id(1)));
        append_ok(&state_store, state(1, Some(head0), lease_id(2)));
        let latest = run_async(state_store.latest_snapshot()).unwrap().unwrap();
        assert_eq!(latest.1.covers_seq, 1);
    }

    #[test]
    fn read_root_detects_tampered_object_id() {
        let object_store = store();
        let state_store = test_store(object_store.clone());
        let mut root = root_with_head(None, 11);
        let mut stored = state_store
            .stored_object(&root.header, &root, RetentionClass::Pinned)
            .unwrap();
        stored.object_id = ObjectId::from_bytes([7; 32]);
        root.header.created_at = 12;
        run_async(object_store.put(stored)).unwrap();
        let err = run_async(state_store.read_root()).unwrap_err();
        assert!(matches!(
            err,
            ConnectorStateStoreError::ContentIdMismatch { .. }
        ));
    }

    #[test]
    fn read_chain_detects_header_body_mismatch() {
        let object_store = store();
        let state_store = test_store(object_store.clone());
        let state_obj = state(0, None, lease_id(1));
        let mut stored = state_store
            .stored_object(&state_obj.header, &state_obj, RetentionClass::Pinned)
            .unwrap();
        stored.header.created_at += 1;
        stored.object_id =
            StoredObject::derive_id(&stored.header, &stored.body, &object_id_key()).unwrap();
        run_async(object_store.put(stored)).unwrap();
        let err = run_async(state_store.read_chain(None, 1)).unwrap_err();
        assert!(matches!(err, ConnectorStateStoreError::HeaderBodyMismatch));
    }

    #[test]
    fn root_requires_head_reference() {
        let state_store = test_store(store());
        let mut root = root_with_head(Some(ObjectId::from_bytes([5; 32])), 11);
        root.header.refs.clear();
        let err = run_async(state_store.store_root(root)).unwrap_err();
        assert!(matches!(err, ConnectorStateStoreError::MissingHead(_)));
    }
}
