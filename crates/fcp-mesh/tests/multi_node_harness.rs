#![forbid(unsafe_code)]

use std::cmp::Ordering;
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use fcp_async_core::channel::{mpsc, oneshot};
use fcp_async_core::{AsyncError, TaskGroup, task, time};
use fcp_core::{EpochId, ObjectId, TailscaleNodeId, ZoneId};
use fcp_crypto::{Ed25519SigningKey, Ed25519VerifyingKey, X25519PublicKey, X25519SecretKey};
use fcp_mesh::{
    AvailabilityProfile, CpuArch, DeviceProfile, GossipMessage, GossipRequest, LatencyClass,
    MeshNode, MeshNodeConfig, ObjectAdmissionClass, PowerSource,
};
use fcp_store::{
    MemoryObjectStore, MemoryObjectStoreConfig, MemorySymbolStore, MemorySymbolStoreConfig,
    ObjectAdmissionPolicy, ObjectSymbolMeta, QuarantineStore, StoredSymbol,
};
use fcp_tailscale::NodeId;
use thiserror::Error;

const NODE_COUNT: usize = 3;
const NODE_EVENT_CHANNEL_CAPACITY: usize = 160;
const OUTBOUND_CHANNEL_CAPACITY: usize = 128;
const CONTROL_REPLY_TIMEOUT: Duration = Duration::from_secs(5);
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const FLUSH_TIMEOUT: Duration = Duration::from_secs(5);
const FLUSH_SETTLE_YIELDS: usize = 8;
const FLUSH_IDLE_ROUNDS: usize = 2;

#[derive(Debug, Clone)]
pub struct NodePublicIdentity {
    pub node_id: NodeId,
    pub signing_public_key: Ed25519VerifyingKey,
    pub encryption_public_key: X25519PublicKey,
    pub issuance_public_key: Ed25519VerifyingKey,
}

#[derive(Debug, Clone)]
pub struct NodeIdentity {
    pub node_id: NodeId,
    pub signing_key: Ed25519SigningKey,
    pub encryption_key: X25519SecretKey,
    pub issuance_key: Ed25519SigningKey,
}

impl NodeIdentity {
    #[must_use]
    pub fn public_identity(&self) -> NodePublicIdentity {
        NodePublicIdentity {
            node_id: self.node_id.clone(),
            signing_public_key: self.signing_key.verifying_key(),
            encryption_public_key: self.encryption_key.public_key(),
            issuance_public_key: self.issuance_key.verifying_key(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ObservedMessage {
    pub from: NodeId,
    pub received_at_ms: u64,
    pub message: GossipMessage,
}

#[derive(Debug, Clone)]
pub struct NodeSnapshot {
    pub node_id: NodeId,
    pub peer_count: usize,
    pub known_objects: Vec<ObjectId>,
    pub observed_messages: Vec<ObservedMessage>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryDisposition {
    Queued,
    DroppedByPartition,
    DroppedByPacketLoss,
}

#[derive(Debug, Error)]
pub enum HarnessError {
    #[error("node `{0}` is not part of the harness")]
    UnknownNode(String),
    #[error("control channel `{0}` is closed")]
    ControlChannelClosed(&'static str),
    #[error("network channel for `{0}` is closed")]
    NetworkChannelClosed(String),
    #[error("oneshot reply channel dropped before sending a response")]
    ReplyDropped,
    #[error("timed out waiting {timeout_ms}ms for `{operation}` reply")]
    ReplyTimeout {
        operation: &'static str,
        timeout_ms: u64,
    },
    #[error("timed out after {timeout_ms}ms during `{operation}`")]
    OperationTimeout {
        operation: &'static str,
        timeout_ms: u64,
    },
    #[error("async runtime error: {0}")]
    Async(#[from] AsyncError),
}

#[derive(Debug)]
struct NodeHandle {
    identity: NodeIdentity,
    event_tx: mpsc::Sender<NodeEvent>,
}

#[derive(Debug, Clone)]
struct LinkBehavior {
    latency: Duration,
    packet_loss: f64,
}

impl Default for LinkBehavior {
    fn default() -> Self {
        Self {
            latency: Duration::ZERO,
            packet_loss: 0.0,
        }
    }
}

#[derive(Debug)]
struct PendingDelivery {
    deliver_at_ms: u64,
    envelope: InboundEnvelope,
}

impl Ord for PendingDelivery {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .deliver_at_ms
            .cmp(&self.deliver_at_ms)
            .then_with(|| {
                self.envelope
                    .from
                    .as_str()
                    .cmp(other.envelope.from.as_str())
            })
            .then_with(|| self.envelope.to.as_str().cmp(other.envelope.to.as_str()))
    }
}

impl PartialOrd for PendingDelivery {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for PendingDelivery {
    fn eq(&self, other: &Self) -> bool {
        self.deliver_at_ms == other.deliver_at_ms
            && self.envelope.from == other.envelope.from
            && self.envelope.to == other.envelope.to
    }
}

impl Eq for PendingDelivery {}

#[derive(Debug)]
struct InboundEnvelope {
    from: NodeId,
    to: NodeId,
    delivered_at_ms: u64,
    message: GossipMessage,
}

#[derive(Debug)]
struct OutboundEnvelope {
    from: NodeId,
    to: NodeId,
    created_at_ms: u64,
    message: GossipMessage,
}

#[derive(Debug)]
enum NodeCommand {
    RegisterPeers {
        peers: Vec<NodePublicIdentity>,
        now_ms: u64,
        reply: oneshot::Sender<()>,
    },
    AnnounceObject {
        zone_id: ZoneId,
        object_id: ObjectId,
        admission: ObjectAdmissionClass,
        now_ms: u64,
        reply: oneshot::Sender<bool>,
    },
    AnnounceSymbol {
        zone_id: ZoneId,
        object_id: ObjectId,
        esi: u32,
        admission: ObjectAdmissionClass,
        now_ms: u64,
        reply: oneshot::Sender<bool>,
    },
    StoreObjectMeta {
        meta: ObjectSymbolMeta,
        reply: oneshot::Sender<()>,
    },
    StoreSymbol {
        symbol: StoredSymbol,
        reply: oneshot::Sender<()>,
    },
    CanReconstruct {
        object_id: ObjectId,
        reply: oneshot::Sender<bool>,
    },
    CreateSummary {
        zone_id: ZoneId,
        epoch_id: EpochId,
        reply: oneshot::Sender<Option<fcp_mesh::GossipSummary>>,
    },
    CreateObjectRequest {
        zone_id: ZoneId,
        object_ids: Vec<ObjectId>,
        now_secs: u64,
        reply: oneshot::Sender<GossipRequest>,
    },
    CreateSymbolRequest {
        zone_id: ZoneId,
        symbols: Vec<(ObjectId, u32)>,
        now_secs: u64,
        reply: oneshot::Sender<GossipRequest>,
    },
    Snapshot {
        zone_id: ZoneId,
        limit: usize,
        reply: oneshot::Sender<NodeSnapshot>,
    },
    Shutdown,
}

#[derive(Debug)]
enum NodeEvent {
    Command(NodeCommand),
    Network(InboundEnvelope),
}

pub struct MultiNodeMeshHarness {
    now_ms: u64,
    rng_state: u64,
    nodes: BTreeMap<String, NodeHandle>,
    pending: BinaryHeap<PendingDelivery>,
    link_behaviors: HashMap<(String, String), LinkBehavior>,
    partitions: Vec<HashSet<String>>,
    outbound_rx: mpsc::Receiver<OutboundEnvelope>,
    tasks: TaskGroup,
}

impl MultiNodeMeshHarness {
    pub async fn new_three_node(seed: u64) -> Result<Self, HarnessError> {
        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_CHANNEL_CAPACITY);
        let mut tasks = TaskGroup::new();
        let mut nodes = BTreeMap::new();

        for index in 0..NODE_COUNT {
            let node_name = format!("mesh-harness-node-{}", index + 1);
            let identity = derive_identity(seed, &node_name);
            let sender_instance_id = derive_u64(seed, &node_name, "sender-instance");
            let local_node_id = derive_u64(seed, &node_name, "symbol-store-node");
            let mesh_node = build_mesh_node(&node_name, sender_instance_id, local_node_id);

            let (event_tx, event_rx) = mpsc::channel(NODE_EVENT_CHANNEL_CAPACITY);

            tasks.spawn(
                format!("multi-node-harness-{node_name}"),
                run_node_task(identity.clone(), mesh_node, event_rx, outbound_tx.clone()),
            );

            nodes.insert(node_name, NodeHandle { identity, event_tx });
        }

        Ok(Self {
            now_ms: 0,
            rng_state: seed.max(1),
            nodes,
            pending: BinaryHeap::new(),
            link_behaviors: HashMap::new(),
            partitions: Vec::new(),
            outbound_rx,
            tasks,
        })
    }

    #[must_use]
    pub fn node_ids(&self) -> Vec<NodeId> {
        self.nodes
            .values()
            .map(|handle| handle.identity.node_id.clone())
            .collect()
    }

    #[must_use]
    pub fn public_identities(&self) -> Vec<NodePublicIdentity> {
        self.nodes
            .values()
            .map(|handle| handle.identity.public_identity())
            .collect()
    }

    #[must_use]
    pub fn now_ms(&self) -> u64 {
        self.now_ms
    }

    #[must_use]
    pub fn pending_message_count(&self) -> usize {
        self.pending.len()
    }

    pub fn set_latency(&mut self, from: &NodeId, to: &NodeId, latency: Duration) {
        self.link_behaviors
            .entry(link_key(from, to))
            .or_default()
            .latency = latency;
    }

    pub fn set_bidirectional_latency(&mut self, left: &NodeId, right: &NodeId, latency: Duration) {
        self.set_latency(left, right, latency);
        self.set_latency(right, left, latency);
    }

    pub fn set_packet_loss(&mut self, from: &NodeId, to: &NodeId, packet_loss: f64) {
        self.link_behaviors
            .entry(link_key(from, to))
            .or_default()
            .packet_loss = packet_loss.clamp(0.0, 1.0);
    }

    pub fn set_bidirectional_packet_loss(
        &mut self,
        left: &NodeId,
        right: &NodeId,
        packet_loss: f64,
    ) {
        self.set_packet_loss(left, right, packet_loss);
        self.set_packet_loss(right, left, packet_loss);
    }

    pub fn partition(&mut self, isolated: &[NodeId]) {
        let members = isolated
            .iter()
            .map(|node_id| node_id.as_str().to_string())
            .collect::<HashSet<_>>();
        self.partitions.push(members);
    }

    pub fn heal_partitions(&mut self) {
        self.partitions.clear();
    }

    pub async fn register_all_peers(&mut self) -> Result<(), HarnessError> {
        let peers = self.public_identities();
        let now_ms = self.now_ms;

        for handle in self.nodes.values() {
            let (reply_tx, reply_rx) = oneshot::channel();
            send_with_timeout(
                &handle.event_tx,
                NodeCommand::RegisterPeers {
                    peers: peers.clone(),
                    now_ms,
                    reply: reply_tx,
                },
                "register_peers",
            )
            .await?;
            await_reply("register_peers", reply_rx).await?;
        }

        Ok(())
    }

    pub async fn announce_object(
        &mut self,
        node_id: &NodeId,
        zone_id: ZoneId,
        object_id: ObjectId,
        admission: ObjectAdmissionClass,
    ) -> Result<bool, HarnessError> {
        let handle = self.node_handle(node_id)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        send_with_timeout(
            &handle.event_tx,
            NodeCommand::AnnounceObject {
                zone_id,
                object_id,
                admission,
                now_ms: self.now_ms,
                reply: reply_tx,
            },
            "announce_object",
        )
        .await?;
        await_reply("announce_object", reply_rx).await
    }

    pub async fn announce_symbol(
        &mut self,
        node_id: &NodeId,
        zone_id: ZoneId,
        object_id: ObjectId,
        esi: u32,
        admission: ObjectAdmissionClass,
    ) -> Result<bool, HarnessError> {
        let handle = self.node_handle(node_id)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        send_with_timeout(
            &handle.event_tx,
            NodeCommand::AnnounceSymbol {
                zone_id,
                object_id,
                esi,
                admission,
                now_ms: self.now_ms,
                reply: reply_tx,
            },
            "announce_symbol",
        )
        .await?;
        await_reply("announce_symbol", reply_rx).await
    }

    pub async fn store_object_meta(
        &mut self,
        node_id: &NodeId,
        meta: ObjectSymbolMeta,
    ) -> Result<(), HarnessError> {
        let handle = self.node_handle(node_id)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        send_with_timeout(
            &handle.event_tx,
            NodeCommand::StoreObjectMeta {
                meta,
                reply: reply_tx,
            },
            "store_object_meta",
        )
        .await?;
        await_reply("store_object_meta", reply_rx).await
    }

    pub async fn store_symbol(
        &mut self,
        node_id: &NodeId,
        symbol: StoredSymbol,
    ) -> Result<(), HarnessError> {
        let handle = self.node_handle(node_id)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        send_with_timeout(
            &handle.event_tx,
            NodeCommand::StoreSymbol {
                symbol,
                reply: reply_tx,
            },
            "store_symbol",
        )
        .await?;
        await_reply("store_symbol", reply_rx).await
    }

    pub async fn can_reconstruct(
        &mut self,
        node_id: &NodeId,
        object_id: ObjectId,
    ) -> Result<bool, HarnessError> {
        let handle = self.node_handle(node_id)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        send_with_timeout(
            &handle.event_tx,
            NodeCommand::CanReconstruct {
                object_id,
                reply: reply_tx,
            },
            "can_reconstruct",
        )
        .await?;
        await_reply("can_reconstruct", reply_rx).await
    }

    pub async fn send_summary(
        &mut self,
        from: &NodeId,
        to: &NodeId,
        zone_id: ZoneId,
        epoch_id: EpochId,
    ) -> Result<DeliveryDisposition, HarnessError> {
        let handle = self.node_handle(from)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        send_with_timeout(
            &handle.event_tx,
            NodeCommand::CreateSummary {
                zone_id,
                epoch_id,
                reply: reply_tx,
            },
            "create_summary",
        )
        .await?;

        let Some(summary) = await_reply("create_summary", reply_rx).await? else {
            return Ok(DeliveryDisposition::Queued);
        };

        let disposition =
            self.schedule_message(from, to, GossipMessage::Summary(summary), self.now_ms);
        self.flush().await?;
        Ok(disposition)
    }

    pub async fn broadcast_summaries(
        &mut self,
        zone_id: ZoneId,
        epoch_id: EpochId,
    ) -> Result<(), HarnessError> {
        let node_ids = self.node_ids();
        for from in &node_ids {
            for to in &node_ids {
                if from != to {
                    let _ = self
                        .send_summary(from, to, zone_id.clone(), epoch_id.clone())
                        .await?;
                }
            }
        }
        Ok(())
    }

    pub async fn request_objects(
        &mut self,
        requester: &NodeId,
        responder: &NodeId,
        zone_id: ZoneId,
        object_ids: Vec<ObjectId>,
    ) -> Result<DeliveryDisposition, HarnessError> {
        let observed_before = self
            .snapshot(requester, zone_id.clone(), 0)
            .await?
            .observed_messages
            .len();
        let handle = self.node_handle(requester)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        send_with_timeout(
            &handle.event_tx,
            NodeCommand::CreateObjectRequest {
                zone_id: zone_id.clone(),
                object_ids,
                now_secs: self.now_ms / 1000,
                reply: reply_tx,
            },
            "create_object_request",
        )
        .await?;
        let request = await_reply("create_object_request", reply_rx).await?;
        let disposition = self.schedule_message(
            requester,
            responder,
            GossipMessage::Request(request),
            self.now_ms,
        );
        self.flush().await?;
        if disposition == DeliveryDisposition::Queued {
            self.wait_for_observed_response(requester, responder, zone_id, observed_before)
                .await?;
        }
        Ok(disposition)
    }

    pub async fn request_symbols(
        &mut self,
        requester: &NodeId,
        responder: &NodeId,
        zone_id: ZoneId,
        symbols: Vec<(ObjectId, u32)>,
    ) -> Result<DeliveryDisposition, HarnessError> {
        let observed_before = self
            .snapshot(requester, zone_id.clone(), 0)
            .await?
            .observed_messages
            .len();
        let handle = self.node_handle(requester)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        send_with_timeout(
            &handle.event_tx,
            NodeCommand::CreateSymbolRequest {
                zone_id: zone_id.clone(),
                symbols,
                now_secs: self.now_ms / 1000,
                reply: reply_tx,
            },
            "create_symbol_request",
        )
        .await?;
        let request = await_reply("create_symbol_request", reply_rx).await?;
        let disposition = self.schedule_message(
            requester,
            responder,
            GossipMessage::Request(request),
            self.now_ms,
        );
        self.flush().await?;
        if disposition == DeliveryDisposition::Queued {
            self.wait_for_observed_response(requester, responder, zone_id, observed_before)
                .await?;
        }
        Ok(disposition)
    }

    pub async fn snapshot(
        &mut self,
        node_id: &NodeId,
        zone_id: ZoneId,
        limit: usize,
    ) -> Result<NodeSnapshot, HarnessError> {
        let handle = self.node_handle(node_id)?;
        let (reply_tx, reply_rx) = oneshot::channel();
        send_with_timeout(
            &handle.event_tx,
            NodeCommand::Snapshot {
                zone_id,
                limit,
                reply: reply_tx,
            },
            "snapshot",
        )
        .await?;
        await_reply("snapshot", reply_rx).await
    }

    async fn wait_for_observed_response(
        &mut self,
        requester: &NodeId,
        responder: &NodeId,
        zone_id: ZoneId,
        observed_before: usize,
    ) -> Result<(), HarnessError> {
        time::timeout(CONTROL_REPLY_TIMEOUT, async {
            loop {
                self.flush().await?;
                let snapshot = self.snapshot(requester, zone_id.clone(), 0).await?;
                if snapshot
                    .observed_messages
                    .iter()
                    .skip(observed_before)
                    .any(|entry| {
                        entry.from == *responder
                            && matches!(entry.message, GossipMessage::Response(_))
                    })
                {
                    return Ok(());
                }

                task::yield_now().await;
            }
        })
        .await
        .map_err(|_| HarnessError::ReplyTimeout {
            operation: "wait_for_observed_response",
            timeout_ms: u64::try_from(CONTROL_REPLY_TIMEOUT.as_millis()).unwrap_or(u64::MAX),
        })?
    }

    pub async fn advance_time(&mut self, duration: Duration) -> Result<(), HarnessError> {
        let delta_ms = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        self.now_ms = self.now_ms.saturating_add(delta_ms);
        self.flush().await
    }

    pub async fn shutdown(self) -> Result<(), HarnessError> {
        for handle in self.nodes.values() {
            send_with_timeout(&handle.event_tx, NodeCommand::Shutdown, "shutdown").await?;
        }
        self.tasks.shutdown(Duration::from_secs(1)).await?;
        Ok(())
    }

    fn schedule_message(
        &mut self,
        from: &NodeId,
        to: &NodeId,
        message: GossipMessage,
        created_at_ms: u64,
    ) -> DeliveryDisposition {
        if self.is_partitioned(from, to) {
            return DeliveryDisposition::DroppedByPartition;
        }

        let behavior = self
            .link_behaviors
            .get(&link_key(from, to))
            .cloned()
            .unwrap_or_default();
        if self.should_drop(behavior.packet_loss) {
            return DeliveryDisposition::DroppedByPacketLoss;
        }

        let delay_ms = u64::try_from(behavior.latency.as_millis()).unwrap_or(u64::MAX);
        let delivered_at_ms = created_at_ms.saturating_add(delay_ms);
        self.pending.push(PendingDelivery {
            deliver_at_ms: delivered_at_ms,
            envelope: InboundEnvelope {
                from: from.clone(),
                to: to.clone(),
                delivered_at_ms,
                message,
            },
        });
        DeliveryDisposition::Queued
    }

    async fn flush(&mut self) -> Result<(), HarnessError> {
        time::timeout(FLUSH_TIMEOUT, self.flush_inner())
            .await
            .map_err(|_| HarnessError::OperationTimeout {
                operation: "flush",
                timeout_ms: u64::try_from(FLUSH_TIMEOUT.as_millis()).unwrap_or(u64::MAX),
            })?
    }

    async fn flush_inner(&mut self) -> Result<(), HarnessError> {
        let mut idle_rounds = 0usize;

        loop {
            self.pump_outbound();

            let mut delivered = 0usize;
            while let Some(delivery) = self.pop_ready() {
                let event_tx = self.node_handle(&delivery.envelope.to)?.event_tx.clone();
                let recipient = delivery.envelope.to.as_str().to_string();
                time::timeout(
                    IO_TIMEOUT,
                    event_tx.send(NodeEvent::Network(delivery.envelope)),
                )
                .await
                .map_err(|_| HarnessError::OperationTimeout {
                    operation: "network_send",
                    timeout_ms: u64::try_from(IO_TIMEOUT.as_millis()).unwrap_or(u64::MAX),
                })?
                .map_err(|_| HarnessError::NetworkChannelClosed(recipient))?;
                delivered += 1;
            }

            // Yield/pump in bounded rounds so request handling can surface outbound
            // responses before we declare the harness quiescent.
            for _ in 0..FLUSH_SETTLE_YIELDS {
                task::yield_now().await;
                self.pump_outbound();
                if self.has_ready_messages() {
                    break;
                }
            }

            if delivered == 0 && !self.has_ready_messages() {
                idle_rounds += 1;
                if idle_rounds >= FLUSH_IDLE_ROUNDS {
                    break;
                }
            } else {
                idle_rounds = 0;
            }
        }

        Ok(())
    }

    fn pump_outbound(&mut self) {
        loop {
            match self.outbound_rx.try_recv() {
                Ok(outbound) => {
                    let _ = self.schedule_message(
                        &outbound.from,
                        &outbound.to,
                        outbound.message,
                        outbound.created_at_ms,
                    );
                }
                Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected) => {
                    break;
                }
            }
        }
    }

    fn has_ready_messages(&self) -> bool {
        self.pending
            .peek()
            .is_some_and(|delivery| delivery.deliver_at_ms <= self.now_ms)
    }

    fn pop_ready(&mut self) -> Option<PendingDelivery> {
        if self
            .pending
            .peek()
            .is_some_and(|delivery| delivery.deliver_at_ms <= self.now_ms)
        {
            self.pending.pop()
        } else {
            None
        }
    }

    fn node_handle(&self, node_id: &NodeId) -> Result<&NodeHandle, HarnessError> {
        self.nodes
            .get(node_id.as_str())
            .ok_or_else(|| HarnessError::UnknownNode(node_id.as_str().to_string()))
    }

    fn is_partitioned(&self, from: &NodeId, to: &NodeId) -> bool {
        self.partitions.iter().any(|partition| {
            let from_in = partition.contains(from.as_str());
            let to_in = partition.contains(to.as_str());
            from_in ^ to_in
        })
    }

    fn should_drop(&mut self, packet_loss: f64) -> bool {
        if packet_loss <= 0.0 {
            return false;
        }
        if packet_loss >= 1.0 {
            return true;
        }

        self.rng_state = self
            .rng_state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        #[allow(clippy::cast_precision_loss)]
        let sample = (self.rng_state >> 11) as f64 / ((u64::MAX >> 11) as f64);
        sample < packet_loss
    }
}

fn link_key(from: &NodeId, to: &NodeId) -> (String, String) {
    (from.as_str().to_string(), to.as_str().to_string())
}

async fn run_node_task(
    identity: NodeIdentity,
    mut mesh: MeshNode,
    mut event_rx: mpsc::Receiver<NodeEvent>,
    outbound_tx: mpsc::Sender<OutboundEnvelope>,
) -> Result<(), AsyncError> {
    let mut observed_messages = Vec::new();

    while let Some(event) = event_rx.recv().await {
        match event {
            NodeEvent::Command(command) => match command {
                NodeCommand::RegisterPeers {
                    peers,
                    now_ms,
                    reply,
                } => {
                    mesh.update_local_state(
                        default_profile(&identity.node_id),
                        HashSet::new(),
                        Vec::new(),
                    );
                    for peer in peers {
                        if peer.node_id == identity.node_id {
                            continue;
                        }
                        mesh.update_peer_state(
                            peer.node_id.clone(),
                            default_profile(&peer.node_id),
                            HashSet::new(),
                            Vec::new(),
                            now_ms,
                        );
                        mesh.register_peer_signing_key(peer.node_id, peer.signing_public_key);
                    }
                    let _ = reply.send(());
                }
                NodeCommand::AnnounceObject {
                    zone_id,
                    object_id,
                    admission,
                    now_ms,
                    reply,
                } => {
                    let added = mesh.announce_object(&zone_id, &object_id, admission, now_ms);
                    let _ = reply.send(added);
                }
                NodeCommand::AnnounceSymbol {
                    zone_id,
                    object_id,
                    esi,
                    admission,
                    now_ms,
                    reply,
                } => {
                    let added = mesh.announce_symbol(&zone_id, &object_id, esi, admission, now_ms);
                    let _ = reply.send(added);
                }
                NodeCommand::StoreObjectMeta { meta, reply } => {
                    mesh.symbol_store()
                        .put_object_meta(meta)
                        .await
                        .expect("storing object metadata in harness should succeed");
                    let _ = reply.send(());
                }
                NodeCommand::StoreSymbol { symbol, reply } => {
                    mesh.symbol_store()
                        .put_symbol(symbol)
                        .await
                        .expect("storing symbols in harness should succeed");
                    let _ = reply.send(());
                }
                NodeCommand::CanReconstruct { object_id, reply } => {
                    let result = mesh.symbol_store().can_reconstruct(&object_id).await;
                    let _ = reply.send(result);
                }
                NodeCommand::CreateSummary {
                    zone_id,
                    epoch_id,
                    reply,
                } => {
                    let summary = mesh.gossip_mut().create_summary(&zone_id, epoch_id);
                    let _ = reply.send(summary);
                }
                NodeCommand::CreateObjectRequest {
                    zone_id,
                    object_ids,
                    now_secs,
                    reply,
                } => {
                    let request = mesh
                        .gossip_mut()
                        .create_request(&zone_id, object_ids, now_secs);
                    let _ = reply.send(request);
                }
                NodeCommand::CreateSymbolRequest {
                    zone_id,
                    symbols,
                    now_secs,
                    reply,
                } => {
                    let request = GossipRequest::for_symbols(
                        TailscaleNodeId::new(identity.node_id.as_str()),
                        zone_id,
                        symbols,
                        now_secs,
                    );
                    let _ = reply.send(request);
                }
                NodeCommand::Snapshot {
                    zone_id,
                    limit,
                    reply,
                } => {
                    let snapshot = NodeSnapshot {
                        node_id: identity.node_id.clone(),
                        peer_count: mesh.peer_count(),
                        known_objects: mesh.gossip_mut().list_objects_in_zone(&zone_id, limit),
                        observed_messages: observed_messages.clone(),
                    };
                    let _ = reply.send(snapshot);
                }
                NodeCommand::Shutdown => return Ok(()),
            },
            NodeEvent::Network(envelope) => {
                let InboundEnvelope {
                    from,
                    delivered_at_ms,
                    message,
                    ..
                } = envelope;
                let observed = ObservedMessage {
                    from: from.clone(),
                    received_at_ms: delivered_at_ms,
                    message: message.clone(),
                };

                match message {
                    GossipMessage::Summary(summary) => {
                        mesh.gossip_mut()
                            .handle_summary(summary, delivered_at_ms / 1000);
                    }
                    GossipMessage::Request(request) => {
                        let response = mesh.gossip_mut().handle_request(&request);
                        let outbound = OutboundEnvelope {
                            from: identity.node_id.clone(),
                            to: NodeId::new(request.from.as_str()),
                            created_at_ms: delivered_at_ms,
                            message: GossipMessage::Response(response),
                        };
                        outbound_tx
                            .send(outbound)
                            .await
                            .map_err(|_| AsyncError::ChannelClosed)?;
                    }
                    GossipMessage::Response(_response) => {}
                    GossipMessage::ReconcileRequest(_request) => {}
                    GossipMessage::ReconcileResponse(_response) => {}
                }

                observed_messages.push(observed);
            }
        }
    }

    Ok(())
}

fn build_mesh_node(name: &str, sender_instance_id: u64, local_node_id: u64) -> MeshNode {
    let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
    let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig {
        local_node_id,
        ..MemorySymbolStoreConfig::default()
    }));
    let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

    MeshNode::new(
        MeshNodeConfig::new(name).with_sender_instance_id(sender_instance_id),
        object_store,
        symbol_store,
        quarantine_store,
    )
}

fn default_profile(node_id: &NodeId) -> DeviceProfile {
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

fn derive_identity(seed: u64, node_name: &str) -> NodeIdentity {
    let signing_seed = derive_key_material(seed, node_name, "signing");
    let encryption_seed = derive_key_material(seed, node_name, "encryption");
    let issuance_seed = derive_key_material(seed, node_name, "issuance");

    NodeIdentity {
        node_id: NodeId::new(node_name),
        signing_key: Ed25519SigningKey::from_bytes(&signing_seed)
            .expect("derived signing seed should be valid"),
        encryption_key: X25519SecretKey::from_bytes(encryption_seed),
        issuance_key: Ed25519SigningKey::from_bytes(&issuance_seed)
            .expect("derived issuance seed should be valid"),
    }
}

fn derive_key_material(seed: u64, node_name: &str, purpose: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"fcp-mesh-multi-node-harness");
    hasher.update(&seed.to_le_bytes());
    hasher.update(node_name.as_bytes());
    hasher.update(purpose.as_bytes());
    *hasher.finalize().as_bytes()
}

fn derive_u64(seed: u64, node_name: &str, purpose: &str) -> u64 {
    let bytes = derive_key_material(seed, node_name, purpose);
    let mut value = [0_u8; 8];
    value.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(value)
}

async fn send_with_timeout(
    sender: &mpsc::Sender<NodeEvent>,
    command: NodeCommand,
    operation: &'static str,
) -> Result<(), HarnessError> {
    time::timeout(IO_TIMEOUT, sender.send(NodeEvent::Command(command)))
        .await
        .map_err(|_| HarnessError::OperationTimeout {
            operation,
            timeout_ms: u64::try_from(IO_TIMEOUT.as_millis()).unwrap_or(u64::MAX),
        })?
        .map_err(|_| HarnessError::ControlChannelClosed(operation))
}

async fn await_reply<T>(
    operation: &'static str,
    reply_rx: oneshot::Receiver<T>,
) -> Result<T, HarnessError> {
    time::timeout(CONTROL_REPLY_TIMEOUT, reply_rx)
        .await
        .map_err(|_| HarnessError::ReplyTimeout {
            operation,
            timeout_ms: u64::try_from(CONTROL_REPLY_TIMEOUT.as_millis()).unwrap_or(u64::MAX),
        })?
        .map_err(|_| HarnessError::ReplyDropped)
}

fn test_object_id(label: &str) -> ObjectId {
    ObjectId::from_unscoped_bytes(label.as_bytes())
}

fn test_symbol(
    object_id: ObjectId,
    zone_id: ZoneId,
    esi: u32,
    source_node: u64,
    symbol_size: usize,
) -> StoredSymbol {
    let esi_byte = u8::try_from(esi).unwrap_or(0xFF);
    StoredSymbol {
        meta: fcp_store::SymbolMeta {
            object_id,
            esi,
            zone_id,
            source_node: Some(source_node),
            stored_at: 0,
        },
        data: Bytes::from(vec![esi_byte; symbol_size]),
    }
}

#[fcp_async_core::runtime::test]
async fn multi_node_harness_routes_real_gossip_messages() {
    let zone_id = ZoneId::work();
    let epoch = EpochId::new("epoch-harness");
    let mut harness = MultiNodeMeshHarness::new_three_node(0xC0FFEE)
        .await
        .unwrap();
    harness.register_all_peers().await.unwrap();

    let node_ids = harness.node_ids();
    let node_a = node_ids[0].clone();
    let node_b = node_ids[1].clone();
    let node_c = node_ids[2].clone();

    let object_a = test_object_id("object-a");
    let object_b = test_object_id("object-b");

    assert!(
        harness
            .announce_object(
                &node_a,
                zone_id.clone(),
                object_a,
                ObjectAdmissionClass::Admitted
            )
            .await
            .unwrap()
    );
    assert!(
        harness
            .announce_object(
                &node_a,
                zone_id.clone(),
                object_b,
                ObjectAdmissionClass::Admitted
            )
            .await
            .unwrap()
    );

    harness
        .broadcast_summaries(zone_id.clone(), epoch.clone())
        .await
        .unwrap();
    harness
        .request_objects(&node_b, &node_a, zone_id.clone(), vec![object_a, object_b])
        .await
        .unwrap();
    harness
        .request_objects(&node_c, &node_a, zone_id.clone(), vec![object_b])
        .await
        .unwrap();

    let snapshot_a = harness
        .snapshot(&node_a, zone_id.clone(), 10)
        .await
        .unwrap();
    let snapshot_b = harness
        .snapshot(&node_b, zone_id.clone(), 10)
        .await
        .unwrap();
    let snapshot_c = harness
        .snapshot(&node_c, zone_id.clone(), 10)
        .await
        .unwrap();

    assert_eq!(snapshot_a.peer_count, 2);
    assert_eq!(snapshot_b.peer_count, 2);
    assert_eq!(snapshot_c.peer_count, 2);
    assert_eq!(snapshot_a.known_objects.len(), 2);

    assert!(
        snapshot_b
            .observed_messages
            .iter()
            .any(|entry| matches!(entry.message, GossipMessage::Summary(_))),
        "node-b should observe a summary from node-a"
    );
    assert!(
        snapshot_b
            .observed_messages
            .iter()
            .any(|entry| matches!(&entry.message, GossipMessage::Response(response) if response.have_objects == vec![object_a, object_b])),
        "node-b should observe a concrete gossip response from node-a"
    );
    assert!(
        snapshot_c
            .observed_messages
            .iter()
            .any(|entry| matches!(&entry.message, GossipMessage::Response(response) if response.have_objects == vec![object_b])),
        "node-c should observe a concrete gossip response from node-a"
    );

    harness.shutdown().await.unwrap();
}

#[fcp_async_core::runtime::test]
async fn multi_node_harness_enforces_latency_loss_and_partitions() {
    let zone_id = ZoneId::work();
    let epoch = EpochId::new("epoch-network-controls");
    let mut harness = MultiNodeMeshHarness::new_three_node(0xBAD5EED)
        .await
        .unwrap();
    harness.register_all_peers().await.unwrap();

    let node_ids = harness.node_ids();
    let node_a = node_ids[0].clone();
    let node_b = node_ids[1].clone();
    let node_c = node_ids[2].clone();

    let delayed_object = test_object_id("delayed-object");
    harness
        .announce_object(
            &node_a,
            zone_id.clone(),
            delayed_object,
            ObjectAdmissionClass::Admitted,
        )
        .await
        .unwrap();

    harness.set_latency(&node_a, &node_b, Duration::from_millis(250));
    let disposition = harness
        .send_summary(&node_a, &node_b, zone_id.clone(), epoch.clone())
        .await
        .unwrap();
    assert_eq!(disposition, DeliveryDisposition::Queued);

    let pre_delivery = harness
        .snapshot(&node_b, zone_id.clone(), 10)
        .await
        .unwrap();
    assert!(
        pre_delivery.observed_messages.is_empty(),
        "latency should keep the summary pending until time advances"
    );

    harness
        .advance_time(Duration::from_millis(249))
        .await
        .unwrap();
    let still_pending = harness
        .snapshot(&node_b, zone_id.clone(), 10)
        .await
        .unwrap();
    assert!(
        still_pending.observed_messages.is_empty(),
        "summary should still be pending before latency budget expires"
    );

    harness
        .advance_time(Duration::from_millis(1))
        .await
        .unwrap();
    let delivered = harness
        .snapshot(&node_b, zone_id.clone(), 10)
        .await
        .unwrap();
    assert!(
        delivered
            .observed_messages
            .iter()
            .any(|entry| matches!(entry.message, GossipMessage::Summary(_))),
        "summary should arrive after advancing past the configured latency"
    );

    harness.set_packet_loss(&node_a, &node_c, 1.0);
    let dropped = harness
        .send_summary(&node_a, &node_c, zone_id.clone(), epoch.clone())
        .await
        .unwrap();
    assert_eq!(dropped, DeliveryDisposition::DroppedByPacketLoss);
    let dropped_snapshot = harness
        .snapshot(&node_c, zone_id.clone(), 10)
        .await
        .unwrap();
    assert!(
        dropped_snapshot.observed_messages.is_empty(),
        "100% packet loss should prevent delivery"
    );

    harness.partition(std::slice::from_ref(&node_a));
    let partitioned = harness
        .request_objects(&node_a, &node_b, zone_id.clone(), vec![delayed_object])
        .await
        .unwrap();
    assert_eq!(partitioned, DeliveryDisposition::DroppedByPartition);
    let partitioned_snapshot = harness
        .snapshot(&node_b, zone_id.clone(), 10)
        .await
        .unwrap();
    assert_eq!(
        partitioned_snapshot
            .observed_messages
            .iter()
            .filter(|entry| matches!(entry.message, GossipMessage::Request(_)))
            .count(),
        0,
        "partitioned links should drop request traffic before delivery"
    );

    harness.heal_partitions();
    harness.shutdown().await.unwrap();
}

#[fcp_async_core::runtime::test]
async fn multi_node_harness_supports_symbol_store_seeding() {
    let zone_id = ZoneId::work();
    let object_id = test_object_id("symbol-seeding");
    let mut harness = MultiNodeMeshHarness::new_three_node(0xFACEFEED)
        .await
        .unwrap();
    let node = harness.node_ids()[0].clone();

    let meta = ObjectSymbolMeta {
        object_id,
        zone_id: zone_id.clone(),
        oti: fcp_store::ObjectTransmissionInfo::from(
            fcp_raptorq::ObjectTransmissionInformation::new(256, 64, 1, 1, 1),
        ),
        source_symbols: 3,
        first_symbol_at: 0,
    };

    harness
        .store_object_meta(&node, meta.clone())
        .await
        .unwrap();
    for esi in 0..meta.source_symbols {
        harness
            .store_symbol(&node, test_symbol(object_id, zone_id.clone(), esi, 1, 64))
            .await
            .unwrap();
    }

    assert!(harness.can_reconstruct(&node, object_id).await.unwrap());
    harness.shutdown().await.unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// c73d6.2: Gossip convergence — all 3 nodes agree on object set
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn gossip_convergence_all_nodes_agree_after_exchange() {
    let zone_id = ZoneId::work();
    let epoch = EpochId::new("epoch-convergence");
    let mut harness = MultiNodeMeshHarness::new_three_node(0xC0FFEE_01)
        .await
        .unwrap();
    harness.register_all_peers().await.unwrap();

    let node_ids = harness.node_ids();
    let node_a = node_ids[0].clone();
    let node_b = node_ids[1].clone();
    let node_c = node_ids[2].clone();

    // Node A creates obj_a, Node B creates obj_b
    let obj_a = test_object_id("conv-obj-a");
    let obj_b = test_object_id("conv-obj-b");
    harness
        .announce_object(
            &node_a,
            zone_id.clone(),
            obj_a,
            ObjectAdmissionClass::Admitted,
        )
        .await
        .unwrap();
    harness
        .announce_object(
            &node_b,
            zone_id.clone(),
            obj_b,
            ObjectAdmissionClass::Admitted,
        )
        .await
        .unwrap();

    // Before gossip: each node only knows its own objects
    let snap_a = harness
        .snapshot(&node_a, zone_id.clone(), 10)
        .await
        .unwrap();
    let snap_b = harness
        .snapshot(&node_b, zone_id.clone(), 10)
        .await
        .unwrap();
    let snap_c = harness
        .snapshot(&node_c, zone_id.clone(), 10)
        .await
        .unwrap();
    assert_eq!(snap_a.known_objects.len(), 1, "A should know 1 object");
    assert_eq!(snap_b.known_objects.len(), 1, "B should know 1 object");
    assert_eq!(snap_c.known_objects.len(), 0, "C should know 0 objects");

    // Gossip round 1: broadcast summaries so everyone learns what exists
    harness
        .broadcast_summaries(zone_id.clone(), epoch.clone())
        .await
        .unwrap();

    // Each node requests what it's missing. The gossip response tells them WHAT
    // exists, then the data transfer (simulated here by announce_object on the
    // receiver) makes it locally known.

    // B learns about obj_a from A's summary, requests it, then admits it locally
    let _ = harness
        .request_objects(&node_b, &node_a, zone_id.clone(), vec![obj_a])
        .await;
    harness
        .announce_object(
            &node_b,
            zone_id.clone(),
            obj_a,
            ObjectAdmissionClass::Admitted,
        )
        .await
        .unwrap();

    // A learns about obj_b from B's summary, requests it, then admits it locally
    let _ = harness
        .request_objects(&node_a, &node_b, zone_id.clone(), vec![obj_b])
        .await;
    harness
        .announce_object(
            &node_a,
            zone_id.clone(),
            obj_b,
            ObjectAdmissionClass::Admitted,
        )
        .await
        .unwrap();

    // C learns about both from summaries, requests and admits them
    let _ = harness
        .request_objects(&node_c, &node_a, zone_id.clone(), vec![obj_a])
        .await;
    harness
        .announce_object(
            &node_c,
            zone_id.clone(),
            obj_a,
            ObjectAdmissionClass::Admitted,
        )
        .await
        .unwrap();
    let _ = harness
        .request_objects(&node_c, &node_b, zone_id.clone(), vec![obj_b])
        .await;
    harness
        .announce_object(
            &node_c,
            zone_id.clone(),
            obj_b,
            ObjectAdmissionClass::Admitted,
        )
        .await
        .unwrap();

    // Verify convergence: all 3 nodes have both objects
    let final_a = harness
        .snapshot(&node_a, zone_id.clone(), 10)
        .await
        .unwrap();
    let final_b = harness
        .snapshot(&node_b, zone_id.clone(), 10)
        .await
        .unwrap();
    let final_c = harness
        .snapshot(&node_c, zone_id.clone(), 10)
        .await
        .unwrap();

    assert_eq!(final_a.known_objects.len(), 2, "A should have 2 objects");
    assert_eq!(final_b.known_objects.len(), 2, "B should have 2 objects");
    assert_eq!(final_c.known_objects.len(), 2, "C should have 2 objects");

    // All nodes agree on the exact same set
    let mut a_set: Vec<_> = final_a.known_objects;
    let mut b_set: Vec<_> = final_b.known_objects;
    let mut c_set: Vec<_> = final_c.known_objects;
    a_set.sort();
    b_set.sort();
    c_set.sort();
    assert_eq!(a_set, b_set, "A and B must agree on object set");
    assert_eq!(b_set, c_set, "B and C must agree on object set");

    harness.shutdown().await.unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// c73d6.3: Symbol distribution across 3 nodes
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn symbol_distribution_across_three_nodes() {
    let zone_id = ZoneId::work();
    let object_id = test_object_id("distributed-obj");
    let mut harness = MultiNodeMeshHarness::new_three_node(0xD1575).await.unwrap();
    harness.register_all_peers().await.unwrap();

    let node_ids = harness.node_ids();
    let node_a = node_ids[0].clone();
    let node_b = node_ids[1].clone();
    let node_c = node_ids[2].clone();

    // Configure: K=10 source symbols, 5 repair, symbol_size=64 bytes
    let source_symbols: u32 = 10;
    let repair_symbols: u32 = 5;
    let symbol_size: usize = 64;
    let total_symbols = source_symbols + repair_symbols;

    let meta = ObjectSymbolMeta {
        object_id,
        zone_id: zone_id.clone(),
        oti: fcp_store::ObjectTransmissionInfo::from(
            fcp_raptorq::ObjectTransmissionInformation::new(
                (source_symbols as u64) * (symbol_size as u64),
                symbol_size as u16,
                1,
                1,
                1,
            ),
        ),
        source_symbols,
        first_symbol_at: 0,
    };

    // Store meta on all nodes
    for node in [&node_a, &node_b, &node_c] {
        harness.store_object_meta(node, meta.clone()).await.unwrap();
    }

    // Distribute symbols: A gets [0..5), B gets [5..10), C gets [10..15) (repair)
    for esi in 0..5 {
        harness
            .store_symbol(
                &node_a,
                test_symbol(object_id, zone_id.clone(), esi, 1, symbol_size),
            )
            .await
            .unwrap();
    }
    for esi in 5..10 {
        harness
            .store_symbol(
                &node_b,
                test_symbol(object_id, zone_id.clone(), esi, 2, symbol_size),
            )
            .await
            .unwrap();
    }
    for esi in 10..total_symbols {
        harness
            .store_symbol(
                &node_c,
                test_symbol(object_id, zone_id.clone(), esi, 3, symbol_size),
            )
            .await
            .unwrap();
    }

    // Announce the object from all nodes
    for node in [&node_a, &node_b, &node_c] {
        harness
            .announce_object(
                node,
                zone_id.clone(),
                object_id,
                ObjectAdmissionClass::Admitted,
            )
            .await
            .unwrap();
    }

    // Verify distribution: no single node can reconstruct alone
    // (each has only 5 symbols, need 10)
    assert!(
        !harness.can_reconstruct(&node_a, object_id).await.unwrap(),
        "A alone should NOT be able to reconstruct (has 5/10 symbols)"
    );
    assert!(
        !harness.can_reconstruct(&node_b, object_id).await.unwrap(),
        "B alone should NOT be able to reconstruct (has 5/10 symbols)"
    );
    assert!(
        !harness.can_reconstruct(&node_c, object_id).await.unwrap(),
        "C alone should NOT be able to reconstruct (has 5/10 repair symbols)"
    );

    // Verify each node has exactly its assigned symbols
    let snap_a = harness
        .snapshot(&node_a, zone_id.clone(), 10)
        .await
        .unwrap();
    let snap_b = harness
        .snapshot(&node_b, zone_id.clone(), 10)
        .await
        .unwrap();
    let snap_c = harness
        .snapshot(&node_c, zone_id.clone(), 10)
        .await
        .unwrap();
    assert_eq!(snap_a.known_objects.len(), 1, "A knows 1 object");
    assert_eq!(snap_b.known_objects.len(), 1, "B knows 1 object");
    assert_eq!(snap_c.known_objects.len(), 1, "C knows 1 object");

    harness.shutdown().await.unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// c73d6.4: Object reconstruction from symbols across nodes
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn object_reconstruction_from_distributed_symbols() {
    let zone_id = ZoneId::work();
    let object_id = test_object_id("reconstruct-obj");
    let mut harness = MultiNodeMeshHarness::new_three_node(0xABCDE).await.unwrap();
    harness.register_all_peers().await.unwrap();

    let node_ids = harness.node_ids();
    let node_a = node_ids[0].clone();
    let node_b = node_ids[1].clone();
    let _node_c = node_ids[2].clone();

    let source_symbols: u32 = 6;
    let symbol_size: usize = 64;

    let meta = ObjectSymbolMeta {
        object_id,
        zone_id: zone_id.clone(),
        oti: fcp_store::ObjectTransmissionInfo::from(
            fcp_raptorq::ObjectTransmissionInformation::new(
                (source_symbols as u64) * (symbol_size as u64),
                symbol_size as u16,
                1,
                1,
                1,
            ),
        ),
        source_symbols,
        first_symbol_at: 0,
    };

    // Store meta on node_a
    harness
        .store_object_meta(&node_a, meta.clone())
        .await
        .unwrap();

    // Node A has symbols [0,1,2] - not enough alone (need 6)
    for esi in 0..3 {
        harness
            .store_symbol(
                &node_a,
                test_symbol(object_id, zone_id.clone(), esi, 1, symbol_size),
            )
            .await
            .unwrap();
    }
    assert!(
        !harness.can_reconstruct(&node_a, object_id).await.unwrap(),
        "A with 3/6 symbols should NOT reconstruct"
    );

    // Add symbols [3,4,5] to A (simulating receipt from other nodes via gossip)
    for esi in 3..6 {
        harness
            .store_symbol(
                &node_a,
                test_symbol(object_id, zone_id.clone(), esi, 2, symbol_size),
            )
            .await
            .unwrap();
    }
    assert!(
        harness.can_reconstruct(&node_a, object_id).await.unwrap(),
        "A with 6/6 symbols SHOULD reconstruct (fungibility: any 6 symbols suffice)"
    );

    // Verify insufficient symbols fail
    harness
        .store_object_meta(&node_b, meta.clone())
        .await
        .unwrap();
    for esi in 0..5 {
        harness
            .store_symbol(
                &node_b,
                test_symbol(object_id, zone_id.clone(), esi, 1, symbol_size),
            )
            .await
            .unwrap();
    }
    assert!(
        !harness.can_reconstruct(&node_b, object_id).await.unwrap(),
        "B with 5/6 symbols should NOT reconstruct"
    );

    harness.shutdown().await.unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// c73d6.6: Network partition recovery
// ─────────────────────────────────────────────────────────────────────────────

#[fcp_async_core::runtime::test]
async fn partition_recovery_nodes_reconverge_after_healing() {
    let zone_id = ZoneId::work();
    let epoch = EpochId::new("epoch-partition");
    let mut harness = MultiNodeMeshHarness::new_three_node(0xFADE_01)
        .await
        .unwrap();
    harness.register_all_peers().await.unwrap();

    let node_ids = harness.node_ids();
    let node_a = node_ids[0].clone();
    let node_b = node_ids[1].clone();
    let node_c = node_ids[2].clone();

    // Phase 1: All connected, A creates obj_shared, all converge
    let obj_shared = test_object_id("shared-before-partition");
    harness
        .announce_object(
            &node_a,
            zone_id.clone(),
            obj_shared,
            ObjectAdmissionClass::Admitted,
        )
        .await
        .unwrap();

    // One gossip round to distribute the shared object
    harness
        .broadcast_summaries(zone_id.clone(), epoch.clone())
        .await
        .unwrap();
    let _ = harness
        .request_objects(&node_b, &node_a, zone_id.clone(), vec![obj_shared])
        .await;
    harness
        .announce_object(
            &node_b,
            zone_id.clone(),
            obj_shared,
            ObjectAdmissionClass::Admitted,
        )
        .await
        .unwrap();
    let _ = harness
        .request_objects(&node_c, &node_a, zone_id.clone(), vec![obj_shared])
        .await;
    harness
        .announce_object(
            &node_c,
            zone_id.clone(),
            obj_shared,
            ObjectAdmissionClass::Admitted,
        )
        .await
        .unwrap();

    // Phase 2: PARTITION — isolate node A from {B, C}
    harness.partition(std::slice::from_ref(&node_a));

    // A creates a new object during partition
    let obj_a_during = test_object_id("created-by-a-during-partition");
    harness
        .announce_object(
            &node_a,
            zone_id.clone(),
            obj_a_during,
            ObjectAdmissionClass::Admitted,
        )
        .await
        .unwrap();

    // B creates a new object during partition
    let obj_b_during = test_object_id("created-by-b-during-partition");
    harness
        .announce_object(
            &node_b,
            zone_id.clone(),
            obj_b_during,
            ObjectAdmissionClass::Admitted,
        )
        .await
        .unwrap();

    // Gossip during partition — A's messages to B/C are dropped
    harness
        .broadcast_summaries(zone_id.clone(), epoch.clone())
        .await
        .unwrap();

    // B and C can exchange with each other (not partitioned from each other)
    let _ = harness
        .request_objects(&node_c, &node_b, zone_id.clone(), vec![obj_b_during])
        .await;
    harness
        .announce_object(
            &node_c,
            zone_id.clone(),
            obj_b_during,
            ObjectAdmissionClass::Admitted,
        )
        .await
        .unwrap();

    // Verify: A doesn't know about B's object, B/C don't know about A's
    let snap_a = harness
        .snapshot(&node_a, zone_id.clone(), 10)
        .await
        .unwrap();
    let snap_b = harness
        .snapshot(&node_b, zone_id.clone(), 10)
        .await
        .unwrap();
    assert!(
        !snap_a.known_objects.contains(&obj_b_during),
        "A should NOT know B's object during partition"
    );
    assert!(
        !snap_b.known_objects.contains(&obj_a_during),
        "B should NOT know A's object during partition"
    );

    // Phase 3: HEAL partition
    harness.heal_partitions();

    // Post-healing gossip round to reconverge
    harness
        .broadcast_summaries(zone_id.clone(), epoch.clone())
        .await
        .unwrap();

    // A requests and admits B's object
    let _ = harness
        .request_objects(&node_a, &node_b, zone_id.clone(), vec![obj_b_during])
        .await;
    harness
        .announce_object(
            &node_a,
            zone_id.clone(),
            obj_b_during,
            ObjectAdmissionClass::Admitted,
        )
        .await
        .unwrap();

    // B requests and admits A's object
    let _ = harness
        .request_objects(&node_b, &node_a, zone_id.clone(), vec![obj_a_during])
        .await;
    harness
        .announce_object(
            &node_b,
            zone_id.clone(),
            obj_a_during,
            ObjectAdmissionClass::Admitted,
        )
        .await
        .unwrap();

    // C requests and admits A's object
    let _ = harness
        .request_objects(&node_c, &node_a, zone_id.clone(), vec![obj_a_during])
        .await;
    harness
        .announce_object(
            &node_c,
            zone_id.clone(),
            obj_a_during,
            ObjectAdmissionClass::Admitted,
        )
        .await
        .unwrap();

    // Verify: ALL nodes have ALL objects (convergence after partition heal)
    let final_a = harness
        .snapshot(&node_a, zone_id.clone(), 10)
        .await
        .unwrap();
    let final_b = harness
        .snapshot(&node_b, zone_id.clone(), 10)
        .await
        .unwrap();
    let final_c = harness
        .snapshot(&node_c, zone_id.clone(), 10)
        .await
        .unwrap();

    let expected_objects = vec![obj_shared, obj_a_during, obj_b_during];
    for obj in &expected_objects {
        assert!(
            final_a.known_objects.contains(obj),
            "A should know {obj:?} after partition heal"
        );
        assert!(
            final_b.known_objects.contains(obj),
            "B should know {obj:?} after partition heal"
        );
        assert!(
            final_c.known_objects.contains(obj),
            "C should know {obj:?} after partition heal"
        );
    }

    // No data loss: exactly 3 objects on every node
    assert_eq!(
        final_a.known_objects.len(),
        3,
        "A should have all 3 objects"
    );
    assert_eq!(
        final_b.known_objects.len(),
        3,
        "B should have all 3 objects"
    );
    assert_eq!(
        final_c.known_objects.len(),
        3,
        "C should have all 3 objects"
    );

    harness.shutdown().await.unwrap();
}
