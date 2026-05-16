#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fcp_cbor::{CanonicalSerializer, SchemaId, SerializationError};
use fcp_core::{ConnectorId, ObjectHeader, OperationReceipt, Provenance};
use fcp_crypto::{CryptoError, Ed25519SigningKey, Ed25519VerifyingKey};
use fcp_mesh::{
    AvailabilityProfile, CpuArch, DeviceProfile, LatencyClass, MeshNode, MeshNodeConfig,
    PowerSource,
};
use fcp_prelude::{NodeId as CoreNodeId, NodeSignature, ObjectId, TailscaleNodeId, ZoneId};
use fcp_store::{
    MemoryObjectStore, MemoryObjectStoreConfig, MemorySymbolStore, MemorySymbolStoreConfig,
    ObjectAdmissionPolicy, ObjectStore, QuarantineStore, SymbolStore,
};
use fcp_tailscale::NodeId as MeshNodeId;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use semver::Version;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const DEFAULT_NODE_COUNT: usize = 3;
const DEFAULT_CONNECTOR_ID: &str = "fcp.test.multi-node-failover:utility:1.0.0";
const DEFAULT_ZONE: &str = "z:work";
const SIGNATURE_PLACEHOLDER: [u8; 64] = [0; 64];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalChaosMode {
    NetworkPartitionThenHeal,
    KillLeaderMidWrite,
    KillFollowerMidRead,
}

impl LocalChaosMode {
    #[must_use]
    pub const fn all() -> [Self; 3] {
        [
            Self::NetworkPartitionThenHeal,
            Self::KillLeaderMidWrite,
            Self::KillFollowerMidRead,
        ]
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NetworkPartitionThenHeal => "network_partition_then_heal",
            Self::KillLeaderMidWrite => "kill_leader_mid_write",
            Self::KillFollowerMidRead => "kill_follower_mid_read",
        }
    }

    const fn id(self) -> u8 {
        match self {
            Self::NetworkPartitionThenHeal => 1,
            Self::KillLeaderMidWrite => 2,
            Self::KillFollowerMidRead => 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalNodeRole {
    Candidate,
    Holder,
    Follower,
    Partitioned,
    Offline,
    Recovered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalRoleTransition {
    pub scenario_id: String,
    pub seed_index: u64,
    pub chaos_mode: LocalChaosMode,
    pub node_id_hash: String,
    pub prior_role: LocalNodeRole,
    pub new_role: LocalNodeRole,
    pub lease_handoff_target_hash: Option<String>,
    pub transition_duration_ms: u64,
    pub logical_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalNodeSnapshot {
    pub node_id_hash: String,
    pub role: LocalNodeRole,
    pub online: bool,
    pub peer_count: usize,
    pub local_zone_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalNodeReplayTimeline {
    pub node_id_hash: String,
    pub state_at_t0: LocalNodeSnapshot,
    pub state_at_chaos: LocalNodeSnapshot,
    pub state_at_heal: LocalNodeSnapshot,
    pub state_at_end: LocalNodeSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalReplayManifest {
    pub schema_version: String,
    pub scenario_id: String,
    pub seed_index: u64,
    pub chaos_mode: LocalChaosMode,
    pub node_count: usize,
    pub result: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalReplayHashes {
    pub final_state_hash: String,
    pub receipt_hash: String,
    pub transition_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalReplayBundle {
    pub manifest: LocalReplayManifest,
    pub events: Vec<LocalRoleTransition>,
    pub node_snapshots: Vec<LocalNodeSnapshot>,
    pub node_timelines: Vec<LocalNodeReplayTimeline>,
    pub hashes: LocalReplayHashes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalReplayBundlePaths {
    pub root: PathBuf,
    pub manifest: PathBuf,
    pub events: PathBuf,
    pub hashes: PathBuf,
    pub snapshot_root: PathBuf,
}

impl LocalReplayBundle {
    pub fn events_jsonl(&self) -> Result<String, LocalMeshHarnessError> {
        let mut lines = Vec::with_capacity(self.events.len());
        for event in &self.events {
            lines.push(serde_json::to_string(event)?);
        }
        Ok(lines.join("\n"))
    }

    pub fn is_redaction_safe(&self) -> Result<bool, LocalMeshHarnessError> {
        let bundle = serde_json::to_string(self)?;
        Ok(!bundle.contains("mesh-harness-node-")
            && !bundle.contains("bearer")
            && !bundle.contains("token")
            && !bundle.contains("cookie"))
    }

    pub fn write_to_dir(
        &self,
        root: impl AsRef<Path>,
    ) -> Result<LocalReplayBundlePaths, LocalMeshHarnessError> {
        let root = root.as_ref();
        let manifest = root.join("manifest.json");
        let events = root.join("events.jsonl");
        let hashes = root.join("hashes.json");
        let snapshot_root = root.join("per_node_snapshots");

        fs::create_dir_all(&snapshot_root)?;
        write_json_pretty(&manifest, &self.manifest)?;
        fs::write(&events, self.events_jsonl()?)?;
        write_json_pretty(&hashes, &self.hashes)?;

        for (index, timeline) in self.node_timelines.iter().enumerate() {
            let hash_prefix = timeline.node_id_hash.chars().take(12).collect::<String>();
            let node_dir = snapshot_root.join(format!("node_{index:03}_{hash_prefix}"));
            fs::create_dir_all(&node_dir)?;
            write_snapshot_cbor(&node_dir.join("state_at_t0.cbor"), &timeline.state_at_t0)?;
            write_snapshot_cbor(
                &node_dir.join("state_at_chaos.cbor"),
                &timeline.state_at_chaos,
            )?;
            write_snapshot_cbor(
                &node_dir.join("state_at_heal.cbor"),
                &timeline.state_at_heal,
            )?;
            write_snapshot_cbor(&node_dir.join("state_at_end.cbor"), &timeline.state_at_end)?;
        }

        Ok(LocalReplayBundlePaths {
            root: root.to_path_buf(),
            manifest,
            events,
            hashes,
            snapshot_root,
        })
    }
}

#[derive(Debug, Clone)]
pub struct LocalFailoverOutcome {
    pub scenario_id: String,
    pub final_state_hash: String,
    pub receipt_count: usize,
    pub duplicate_receipt_count: usize,
    pub active_holder_hash: String,
    pub replay_bundle: LocalReplayBundle,
}

#[derive(Debug, Error)]
pub enum LocalMeshHarnessError {
    #[error("local mesh harness requires at least one node")]
    EmptyHarness,
    #[error("no eligible holder for subject `{subject_id}` in zone `{zone_id}`")]
    NoEligibleHolder {
        zone_id: ZoneId,
        subject_id: ObjectId,
    },
    #[error("node `{0}` is not part of the local mesh harness")]
    UnknownNode(String),
    #[error("failed to serialize deterministic harness state: {0}")]
    StateSerialization(#[from] serde_json::Error),
    #[error("failed to write replay bundle artifact: {0}")]
    ReplayArtifactIo(#[from] std::io::Error),
    #[error("failed to serialize replay snapshot as canonical CBOR: {0}")]
    ReplaySnapshotSerialization(#[from] SerializationError),
    #[error("failed to derive deterministic harness signing key: {0}")]
    SigningKey(#[from] CryptoError),
}

struct LocalMeshNode {
    mesh_id: MeshNodeId,
    tailscale_id: TailscaleNodeId,
    signing_key: Ed25519SigningKey,
    mesh: MeshNode,
    role: LocalNodeRole,
    online: bool,
}

pub struct LocalMeshHarness {
    seed_index: u64,
    zone_id: ZoneId,
    connector_id: ConnectorId,
    subject_id: ObjectId,
    nodes: BTreeMap<String, LocalMeshNode>,
    receipts_by_key: BTreeMap<String, OperationReceipt>,
    transitions: Vec<LocalRoleTransition>,
    logical_time_ms: u64,
}

impl LocalMeshHarness {
    pub fn new_three_node(seed_index: u64) -> Result<Self, LocalMeshHarnessError> {
        Self::new(seed_index, DEFAULT_NODE_COUNT)
    }

    pub fn new(seed_index: u64, node_count: usize) -> Result<Self, LocalMeshHarnessError> {
        if node_count == 0 {
            return Err(LocalMeshHarnessError::EmptyHarness);
        }

        let zone_id = ZoneId::work();
        debug_assert_eq!(zone_id.as_str(), DEFAULT_ZONE);
        let connector_id = ConnectorId::from_static(DEFAULT_CONNECTOR_ID);
        let subject_id = singleton_writer_subject_id(&connector_id, &zone_id);
        let mut nodes = BTreeMap::new();

        for index in 0..node_count {
            let node_name = format!("mesh-harness-node-{}", index + 1);
            let mesh_id = MeshNodeId::new(node_name.clone());
            let tailscale_id = TailscaleNodeId::new(node_name.clone());
            let signing_key = deterministic_signing_key(seed_index, &node_name, "signing")?;
            let mesh = build_mesh_node(seed_index, &node_name);

            nodes.insert(
                node_name,
                LocalMeshNode {
                    mesh_id,
                    tailscale_id,
                    signing_key,
                    mesh,
                    role: LocalNodeRole::Candidate,
                    online: true,
                },
            );
        }

        let mut harness = Self {
            seed_index,
            zone_id,
            connector_id,
            subject_id,
            nodes,
            receipts_by_key: BTreeMap::new(),
            transitions: Vec::new(),
            logical_time_ms: 0,
        };
        harness.register_mesh_peers();
        Ok(harness)
    }

    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    #[must_use]
    pub fn mesh_node_count(&self) -> usize {
        self.nodes
            .values()
            .filter(|node| node.mesh.local_zones().contains(&self.zone_id))
            .count()
    }

    pub fn run_failover_scenario(
        &mut self,
        chaos_mode: LocalChaosMode,
    ) -> Result<LocalFailoverOutcome, LocalMeshHarnessError> {
        let scenario_id = format!("seed_{}_{}", self.seed_index, chaos_mode.as_str());
        let mut rng = deterministic_rng(self.seed_index, chaos_mode);
        let initial_holder = self.select_holder()?;
        self.promote_holder(&scenario_id, chaos_mode, &initial_holder, None, &mut rng)?;
        let idempotency_key = format!("{scenario_id}_idem");
        let state_at_t0 = self.node_snapshots();

        let (state_at_chaos, state_at_heal) = match chaos_mode {
            LocalChaosMode::NetworkPartitionThenHeal => {
                self.execute_once(&idempotency_key, &initial_holder)?;
                self.partition_holder(&scenario_id, chaos_mode, &initial_holder, &mut rng)?;
                let state_at_chaos = self.node_snapshots();
                let next_holder = self.select_holder()?;
                self.promote_holder(
                    &scenario_id,
                    chaos_mode,
                    &next_holder,
                    Some(&initial_holder),
                    &mut rng,
                )?;
                self.execute_once(&idempotency_key, &next_holder)?;
                self.recover_node(
                    &scenario_id,
                    chaos_mode,
                    &initial_holder,
                    &next_holder,
                    &mut rng,
                )?;
                let state_at_heal = self.node_snapshots();
                (state_at_chaos, state_at_heal)
            }
            LocalChaosMode::KillLeaderMidWrite => {
                self.kill_node(&scenario_id, chaos_mode, &initial_holder, &mut rng)?;
                let state_at_chaos = self.node_snapshots();
                let next_holder = self.select_holder()?;
                self.promote_holder(
                    &scenario_id,
                    chaos_mode,
                    &next_holder,
                    Some(&initial_holder),
                    &mut rng,
                )?;
                self.execute_once(&idempotency_key, &next_holder)?;
                self.recover_node(
                    &scenario_id,
                    chaos_mode,
                    &initial_holder,
                    &next_holder,
                    &mut rng,
                )?;
                let state_at_heal = self.node_snapshots();
                (state_at_chaos, state_at_heal)
            }
            LocalChaosMode::KillFollowerMidRead => {
                let follower = self.random_follower(&initial_holder, &mut rng)?;
                self.kill_node(&scenario_id, chaos_mode, &follower, &mut rng)?;
                let state_at_chaos = self.node_snapshots();
                self.execute_once(&idempotency_key, &initial_holder)?;
                self.recover_node(
                    &scenario_id,
                    chaos_mode,
                    &follower,
                    &initial_holder,
                    &mut rng,
                )?;
                let state_at_heal = self.node_snapshots();
                (state_at_chaos, state_at_heal)
            }
        };

        let active_holder = self.select_holder()?;
        let final_state_hash = self.final_state_hash()?;
        let state_at_end = self.node_snapshots();
        let node_timelines =
            node_timelines_from_snapshots(state_at_t0, state_at_chaos, state_at_heal, state_at_end);
        let replay_bundle =
            self.replay_bundle(&scenario_id, chaos_mode, &final_state_hash, node_timelines)?;

        Ok(LocalFailoverOutcome {
            scenario_id,
            final_state_hash,
            receipt_count: self.receipts_by_key.len(),
            duplicate_receipt_count: self.duplicate_receipt_count(),
            active_holder_hash: hash_label(active_holder.as_str()),
            replay_bundle,
        })
    }

    fn register_mesh_peers(&mut self) {
        let public_keys = self
            .nodes
            .iter()
            .map(|(name, node)| (name.clone(), node.signing_key.verifying_key()))
            .collect::<BTreeMap<_, Ed25519VerifyingKey>>();
        let peer_profiles = self
            .nodes
            .iter()
            .map(|(name, node)| (name.clone(), default_profile(&node.mesh_id)))
            .collect::<BTreeMap<_, DeviceProfile>>();

        for (name, node) in &mut self.nodes {
            node.mesh.update_local_state(
                default_profile(&node.mesh_id),
                HashSet::new(),
                Vec::new(),
            );
            node.mesh
                .update_local_zones(HashSet::from([self.zone_id.clone()]));

            for (peer_name, peer_profile) in &peer_profiles {
                if peer_name == name {
                    continue;
                }
                let peer_id = MeshNodeId::new(peer_name.clone());
                node.mesh.update_peer_state(
                    peer_id.clone(),
                    peer_profile.clone(),
                    HashSet::new(),
                    Vec::new(),
                    self.logical_time_ms,
                );
                node.mesh
                    .update_peer_zones(&peer_id, HashSet::from([self.zone_id.clone()]));
                if let Some(key) = public_keys.get(peer_name) {
                    node.mesh.register_peer_signing_key(peer_id, key.clone());
                }
            }
        }
    }

    fn select_holder(&self) -> Result<TailscaleNodeId, LocalMeshHarnessError> {
        let eligible_nodes = self
            .nodes
            .values()
            .filter(|node| node.online)
            .map(|node| node.tailscale_id.clone())
            .collect::<Vec<_>>();
        fcp_mesh::planner::select_lease_holder(&self.zone_id, &self.subject_id, &eligible_nodes)
            .ok_or_else(|| LocalMeshHarnessError::NoEligibleHolder {
                zone_id: self.zone_id.clone(),
                subject_id: self.subject_id,
            })
    }

    fn promote_holder(
        &mut self,
        scenario_id: &str,
        chaos_mode: LocalChaosMode,
        holder: &TailscaleNodeId,
        handoff_from: Option<&TailscaleNodeId>,
        rng: &mut ChaCha20Rng,
    ) -> Result<(), LocalMeshHarnessError> {
        let keys = self.nodes.keys().cloned().collect::<Vec<_>>();
        for key in keys {
            let new_role = if key == holder.as_str() {
                LocalNodeRole::Holder
            } else {
                LocalNodeRole::Follower
            };
            self.set_role(
                scenario_id,
                chaos_mode,
                &TailscaleNodeId::new(key),
                new_role,
                handoff_from,
                rng,
            )?;
        }
        Ok(())
    }

    fn partition_holder(
        &mut self,
        scenario_id: &str,
        chaos_mode: LocalChaosMode,
        holder: &TailscaleNodeId,
        rng: &mut ChaCha20Rng,
    ) -> Result<(), LocalMeshHarnessError> {
        let node = self.node_mut(holder)?;
        node.online = false;
        self.set_role(
            scenario_id,
            chaos_mode,
            holder,
            LocalNodeRole::Partitioned,
            None,
            rng,
        )
    }

    fn kill_node(
        &mut self,
        scenario_id: &str,
        chaos_mode: LocalChaosMode,
        node_id: &TailscaleNodeId,
        rng: &mut ChaCha20Rng,
    ) -> Result<(), LocalMeshHarnessError> {
        let node = self.node_mut(node_id)?;
        node.online = false;
        self.set_role(
            scenario_id,
            chaos_mode,
            node_id,
            LocalNodeRole::Offline,
            None,
            rng,
        )
    }

    fn recover_node(
        &mut self,
        scenario_id: &str,
        chaos_mode: LocalChaosMode,
        recovered: &TailscaleNodeId,
        holder: &TailscaleNodeId,
        rng: &mut ChaCha20Rng,
    ) -> Result<(), LocalMeshHarnessError> {
        let node = self.node_mut(recovered)?;
        node.online = true;
        self.set_role(
            scenario_id,
            chaos_mode,
            recovered,
            LocalNodeRole::Recovered,
            Some(holder),
            rng,
        )?;
        self.promote_holder(scenario_id, chaos_mode, holder, Some(recovered), rng)
    }

    fn set_role(
        &mut self,
        scenario_id: &str,
        chaos_mode: LocalChaosMode,
        node_id: &TailscaleNodeId,
        new_role: LocalNodeRole,
        handoff_target: Option<&TailscaleNodeId>,
        rng: &mut ChaCha20Rng,
    ) -> Result<(), LocalMeshHarnessError> {
        let transition_duration_ms = rng.gen_range(5..=50);
        self.logical_time_ms = self.logical_time_ms.saturating_add(transition_duration_ms);
        let node = self.node_mut(node_id)?;
        let prior_role = node.role;
        node.role = new_role;

        if prior_role != new_role {
            self.transitions.push(LocalRoleTransition {
                scenario_id: scenario_id.to_string(),
                seed_index: self.seed_index,
                chaos_mode,
                node_id_hash: hash_label(node_id.as_str()),
                prior_role,
                new_role,
                lease_handoff_target_hash: handoff_target.map(|target| hash_label(target.as_str())),
                transition_duration_ms,
                logical_time_ms: self.logical_time_ms,
            });
        }
        Ok(())
    }

    fn execute_once(
        &mut self,
        idempotency_key: &str,
        holder: &TailscaleNodeId,
    ) -> Result<(), LocalMeshHarnessError> {
        if self.receipts_by_key.contains_key(idempotency_key) {
            return Ok(());
        }

        let signing_key = self.node(holder)?.signing_key.clone();
        let receipt = self.operation_receipt(idempotency_key, holder, &signing_key);
        self.receipts_by_key
            .insert(idempotency_key.to_string(), receipt);
        Ok(())
    }

    fn operation_receipt(
        &self,
        idempotency_key: &str,
        holder: &TailscaleNodeId,
        signing_key: &Ed25519SigningKey,
    ) -> OperationReceipt {
        let request_object_id = object_id_from_label(&format!("request:{idempotency_key}"));
        let outcome_object_id = object_id_from_label(&format!("outcome:{idempotency_key}"));
        let header = ObjectHeader {
            schema: SchemaId::new("fcp.operation", "receipt", Version::new(1, 0, 0)),
            zone_id: self.zone_id.clone(),
            created_at: self.logical_time_ms / 1000,
            provenance: Provenance::new(self.zone_id.clone()),
            refs: vec![request_object_id],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };

        let mut receipt = OperationReceipt {
            header,
            request_object_id,
            idempotency_key: Some(idempotency_key.to_string()),
            outcome_object_ids: vec![outcome_object_id],
            resource_object_ids: Vec::new(),
            usage_metrics: None,
            executed_at: self.logical_time_ms / 1000,
            executed_by: holder.clone(),
            signature: NodeSignature::new(
                CoreNodeId::new(holder.as_str()),
                SIGNATURE_PLACEHOLDER,
                self.logical_time_ms / 1000,
            ),
        };
        let signature = signing_key.sign(&receipt.signable_bytes());
        receipt.signature = NodeSignature::new(
            CoreNodeId::new(holder.as_str()),
            signature.to_bytes(),
            self.logical_time_ms / 1000,
        );
        receipt
    }

    fn random_follower(
        &self,
        holder: &TailscaleNodeId,
        rng: &mut ChaCha20Rng,
    ) -> Result<TailscaleNodeId, LocalMeshHarnessError> {
        let followers = self
            .nodes
            .values()
            .filter(|node| node.online && node.tailscale_id != *holder)
            .map(|node| node.tailscale_id.clone())
            .collect::<Vec<_>>();
        if followers.is_empty() {
            return Err(LocalMeshHarnessError::NoEligibleHolder {
                zone_id: self.zone_id.clone(),
                subject_id: self.subject_id,
            });
        }
        let index = rng.gen_range(0..followers.len());
        followers
            .get(index)
            .cloned()
            .ok_or_else(|| LocalMeshHarnessError::NoEligibleHolder {
                zone_id: self.zone_id.clone(),
                subject_id: self.subject_id,
            })
    }

    fn node(&self, node_id: &TailscaleNodeId) -> Result<&LocalMeshNode, LocalMeshHarnessError> {
        self.nodes
            .get(node_id.as_str())
            .ok_or_else(|| LocalMeshHarnessError::UnknownNode(node_id.as_str().to_string()))
    }

    fn node_mut(
        &mut self,
        node_id: &TailscaleNodeId,
    ) -> Result<&mut LocalMeshNode, LocalMeshHarnessError> {
        self.nodes
            .get_mut(node_id.as_str())
            .ok_or_else(|| LocalMeshHarnessError::UnknownNode(node_id.as_str().to_string()))
    }

    fn duplicate_receipt_count(&self) -> usize {
        let unique_keys = self
            .receipts_by_key
            .values()
            .filter_map(|receipt| receipt.idempotency_key.as_deref())
            .collect::<BTreeSet<_>>()
            .len();
        self.receipts_by_key.len().saturating_sub(unique_keys)
    }

    fn replay_bundle(
        &self,
        scenario_id: &str,
        chaos_mode: LocalChaosMode,
        final_state_hash: &str,
        node_timelines: Vec<LocalNodeReplayTimeline>,
    ) -> Result<LocalReplayBundle, LocalMeshHarnessError> {
        let transition_hash = hash_json(&self.transitions)?;
        let receipt_hash = hash_json(&self.receipts_by_key)?;
        Ok(LocalReplayBundle {
            manifest: LocalReplayManifest {
                schema_version: "1.0.0".to_string(),
                scenario_id: scenario_id.to_string(),
                seed_index: self.seed_index,
                chaos_mode,
                node_count: self.node_count(),
                result: "pass".to_string(),
            },
            events: self.transitions.clone(),
            node_snapshots: self.node_snapshots(),
            node_timelines,
            hashes: LocalReplayHashes {
                final_state_hash: final_state_hash.to_string(),
                receipt_hash,
                transition_hash,
            },
        })
    }

    fn node_snapshots(&self) -> Vec<LocalNodeSnapshot> {
        self.nodes
            .values()
            .map(|node| LocalNodeSnapshot {
                node_id_hash: hash_label(node.tailscale_id.as_str()),
                role: node.role,
                online: node.online,
                peer_count: self.nodes.len().saturating_sub(1),
                local_zone_count: node.mesh.local_zones().len(),
            })
            .collect()
    }

    fn final_state_hash(&self) -> Result<String, LocalMeshHarnessError> {
        #[derive(Serialize)]
        struct ReceiptView<'a> {
            key: &'a str,
            executed_by_hash: String,
            outcome_count: usize,
        }

        #[derive(Serialize)]
        struct StateView<'a> {
            seed_index: u64,
            zone_id: &'a str,
            connector_id: &'a str,
            subject_id: String,
            nodes: Vec<LocalNodeSnapshot>,
            receipts: Vec<ReceiptView<'a>>,
        }

        let receipts = self
            .receipts_by_key
            .iter()
            .map(|(key, receipt)| ReceiptView {
                key: key.as_str(),
                executed_by_hash: hash_label(receipt.executed_by.as_str()),
                outcome_count: receipt.outcome_object_ids.len(),
            })
            .collect::<Vec<_>>();
        let state = StateView {
            seed_index: self.seed_index,
            zone_id: self.zone_id.as_str(),
            connector_id: self.connector_id.as_str(),
            subject_id: self.subject_id.to_string(),
            nodes: self.node_snapshots(),
            receipts,
        };
        Ok(hash_json(&state)?)
    }
}

fn build_mesh_node(seed_index: u64, node_name: &str) -> MeshNode {
    let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
    let object_store: Arc<dyn ObjectStore> = object_store;
    let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig {
        local_node_id: derive_u64(seed_index, node_name, "symbol-store-node"),
        ..MemorySymbolStoreConfig::default()
    }));
    let symbol_store: Arc<dyn SymbolStore> = symbol_store;
    let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

    MeshNode::new(
        MeshNodeConfig::new(node_name).with_sender_instance_id(derive_u64(
            seed_index,
            node_name,
            "sender-instance",
        )),
        object_store,
        symbol_store,
        quarantine_store,
    )
}

fn default_profile(node_id: &MeshNodeId) -> DeviceProfile {
    DeviceProfile::builder(node_id.clone())
        .cpu_cores(4)
        .cpu_arch(CpuArch::X86_64)
        .memory_mb(8192)
        .power_source(PowerSource::Mains)
        .latency_class(LatencyClass::Lan)
        .availability(AvailabilityProfile::AlwaysOn)
        .bandwidth_estimate_kbps(100_000)
        .build()
}

fn deterministic_rng(seed_index: u64, chaos_mode: LocalChaosMode) -> ChaCha20Rng {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"fcp-local-mesh-failover-rng-v1");
    hasher.update(&seed_index.to_le_bytes());
    hasher.update(&[chaos_mode.id()]);
    ChaCha20Rng::from_seed(*hasher.finalize().as_bytes())
}

fn deterministic_signing_key(
    seed_index: u64,
    node_name: &str,
    purpose: &str,
) -> Result<Ed25519SigningKey, LocalMeshHarnessError> {
    Ok(Ed25519SigningKey::from_bytes(&derive_key_material(
        seed_index, node_name, purpose,
    ))?)
}

fn derive_u64(seed_index: u64, node_name: &str, purpose: &str) -> u64 {
    let bytes = derive_key_material(seed_index, node_name, purpose);
    let mut value = [0_u8; 8];
    for (target, source) in value.iter_mut().zip(bytes) {
        *target = source;
    }
    u64::from_le_bytes(value)
}

fn derive_key_material(seed_index: u64, node_name: &str, purpose: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"fcp-local-mesh-harness-key-v1");
    hasher.update(&seed_index.to_le_bytes());
    hasher.update(node_name.as_bytes());
    hasher.update(purpose.as_bytes());
    *hasher.finalize().as_bytes()
}

fn singleton_writer_subject_id(connector_id: &ConnectorId, zone_id: &ZoneId) -> ObjectId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"FCP-HOST-SINGLETON-WRITER-HRW-LEASE-V2");
    update_len_prefixed(&mut hasher, connector_id.as_str().as_bytes());
    update_len_prefixed(&mut hasher, zone_id.as_str().as_bytes());
    ObjectId::from_bytes(*hasher.finalize().as_bytes())
}

fn update_len_prefixed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
}

fn object_id_from_label(label: &str) -> ObjectId {
    ObjectId::from_unscoped_bytes(label.as_bytes())
}

fn node_timelines_from_snapshots(
    state_at_t0: Vec<LocalNodeSnapshot>,
    state_at_chaos: Vec<LocalNodeSnapshot>,
    state_at_heal: Vec<LocalNodeSnapshot>,
    state_at_end: Vec<LocalNodeSnapshot>,
) -> Vec<LocalNodeReplayTimeline> {
    state_at_t0
        .into_iter()
        .zip(state_at_chaos)
        .zip(state_at_heal)
        .zip(state_at_end)
        .map(
            |(((state_at_t0, state_at_chaos), state_at_heal), state_at_end)| {
                LocalNodeReplayTimeline {
                    node_id_hash: state_at_t0.node_id_hash.clone(),
                    state_at_t0,
                    state_at_chaos,
                    state_at_heal,
                    state_at_end,
                }
            },
        )
        .collect()
}

fn write_json_pretty(path: &Path, value: &impl Serialize) -> Result<(), LocalMeshHarnessError> {
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn write_snapshot_cbor(
    path: &Path,
    snapshot: &LocalNodeSnapshot,
) -> Result<(), LocalMeshHarnessError> {
    let schema = SchemaId::new("fcp.testkit", "LocalNodeSnapshot", Version::new(1, 0, 0));
    fs::write(path, CanonicalSerializer::serialize(snapshot, &schema)?)?;
    Ok(())
}

fn hash_label(label: &str) -> String {
    blake3::hash(label.as_bytes()).to_hex().to_string()
}

fn hash_json(value: &impl Serialize) -> Result<String, serde_json::Error> {
    serde_json::to_vec(value).map(|bytes| blake3::hash(&bytes).to_hex().to_string())
}
