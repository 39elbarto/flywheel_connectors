//! Benchmarks for fcp-mesh hot paths.
//!
//! These benchmarks verify performance of the critical mesh operations:
//! - Admission control checks (every incoming request)
//! - Device fitness calculation (execution planning)
//! - Session MAC operations (authenticate each frame)

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::collections::HashSet;
use std::hint::black_box;

use fcp_core::ZoneId;
use fcp_mesh::{
    admission::{AdmissionController, AdmissionPolicy},
    device::{
        AvailabilityProfile, CpuArch, DeviceProfile, FitnessContext, FitnessScore, GpuProfile,
        GpuVendor, InstalledConnector, LatencyClass, PowerSource,
    },
    planner::{
        ExecutionPlanner, NodeInfo, PlacementPolicy, PlannerContext, PlannerInput,
        ResourcePoolClass, ResourcePoolStatus,
    },
    session::MeshSession,
};
use fcp_prelude::{ConnectorId, ObjectId};
use fcp_protocol::session::{
    MeshSessionId, SessionCryptoSuite, SessionKeys, SessionReplayPolicy, TransportLimits,
};
use fcp_tailscale::NodeId;

// ============================================================================
// Admission Control Benchmarks
// ============================================================================

fn bench_admission_check_bytes(c: &mut Criterion) {
    let policy = AdmissionPolicy::default();
    let mut controller = AdmissionController::new(policy);
    let peer = NodeId::new("node-bench-12345");

    c.bench_function("admission_check_bytes", |b| {
        // Each iteration uses a different timestamp to avoid budget exhaustion
        let mut ts = 1_000_000_000u64;
        b.iter(|| {
            ts += 60_000; // Advance 60 seconds to reset window
            let _ = controller.check_bytes(black_box(&peer), black_box(1024), black_box(ts));
        });
    });
}

fn bench_admission_check_symbols(c: &mut Criterion) {
    let policy = AdmissionPolicy::default();
    let mut controller = AdmissionController::new(policy);
    let peer = NodeId::new("node-bench-12345");

    c.bench_function("admission_check_symbols", |b| {
        let mut ts = 1_000_000_000u64;
        b.iter(|| {
            ts += 60_000;
            let _ = controller.check_symbols(black_box(&peer), black_box(10), black_box(ts));
        });
    });
}

fn bench_admission_record_bytes(c: &mut Criterion) {
    let policy = AdmissionPolicy::default();
    let mut controller = AdmissionController::new(policy);
    let peer = NodeId::new("node-bench-12345");

    c.bench_function("admission_record_bytes", |b| {
        let mut ts = 1_000_000_000u64;
        b.iter(|| {
            ts += 60_000;
            controller.record_bytes(black_box(&peer), black_box(1024), black_box(ts));
        });
    });
}

// ============================================================================
// Device Fitness Benchmarks
// ============================================================================

fn bench_fitness_score_basic(c: &mut Criterion) {
    let profile = DeviceProfile::builder(NodeId::new("node-bench-12345"))
        .cpu_cores(8)
        .cpu_arch(CpuArch::X86_64)
        .memory_mb(16_384)
        .power_source(PowerSource::Mains)
        .build();
    let ctx = FitnessContext::new();

    c.bench_function("fitness_score_basic", |b| {
        b.iter(|| {
            let _ = FitnessScore::compute(black_box(&profile), black_box(&ctx));
        });
    });
}

fn bench_fitness_score_with_gpu(c: &mut Criterion) {
    let profile = DeviceProfile::builder(NodeId::new("node-bench-12345"))
        .cpu_cores(16)
        .cpu_arch(CpuArch::X86_64)
        .memory_mb(65_536)
        .power_source(PowerSource::Mains)
        .gpu(GpuProfile::new(GpuVendor::Nvidia, "RTX 4090", 24_576))
        .build();
    let ctx = FitnessContext::new().with_requires_gpu(true);

    c.bench_function("fitness_score_with_gpu", |b| {
        b.iter(|| {
            let _ = FitnessScore::compute(black_box(&profile), black_box(&ctx));
        });
    });
}

fn bench_fitness_score_with_connector(c: &mut Criterion) {
    let connector_id = ConnectorId::new("fcp", "benchmark", "1.0.0").unwrap();
    let profile = DeviceProfile::builder(NodeId::new("node-bench-12345"))
        .cpu_cores(8)
        .cpu_arch(CpuArch::X86_64)
        .memory_mb(16_384)
        .power_source(PowerSource::Mains)
        .add_connector(InstalledConnector::new(
            connector_id.clone(),
            "1.0.0",
            ObjectId::from_bytes([0u8; 32]),
        ))
        .build();
    let ctx = FitnessContext::new().with_required_connector(connector_id);

    c.bench_function("fitness_score_with_connector", |b| {
        b.iter(|| {
            let _ = FitnessScore::compute(black_box(&profile), black_box(&ctx));
        });
    });
}

// ============================================================================
// Resource-Pool Placement Benchmarks
// ============================================================================

fn resource_pool_connector_id() -> ConnectorId {
    ConnectorId::new("fcp", "resource-pool-benchmark", "1.0.0").unwrap()
}

fn make_resource_pool_node(index: usize, connector_id: &ConnectorId, zone: &ZoneId) -> NodeInfo {
    let node_id = NodeId::new(format!("node-{index:03}"));
    let memory_mb = if index == 0 {
        262_144
    } else {
        131_072_u32.saturating_sub(u32::try_from(index).unwrap_or(u32::MAX).saturating_mul(256))
    };

    let profile = DeviceProfile::builder(node_id)
        .cpu_cores(if index == 0 { 64 } else { 32 })
        .cpu_arch(CpuArch::X86_64)
        .memory_mb(memory_mb.max(16_384))
        .power_source(PowerSource::Mains)
        .latency_class(LatencyClass::Local)
        .availability(AvailabilityProfile::AlwaysOn)
        .add_connector(InstalledConnector::new(
            connector_id.clone(),
            "1.0.0",
            ObjectId::from_bytes([index as u8; 32]),
        ))
        .build();

    NodeInfo {
        profile,
        local_symbols: HashSet::new(),
        held_leases: Vec::new(),
        zones: vec![zone.clone()],
    }
}

fn make_resource_pool_input(node_count: usize, zone: &ZoneId) -> PlannerInput {
    let connector_id = resource_pool_connector_id();
    let nodes: Vec<NodeInfo> = (0..node_count)
        .map(|index| make_resource_pool_node(index, &connector_id, zone))
        .collect();
    PlannerInput::new(nodes, 1_000_000)
}

fn attach_resource_pool_state(input: PlannerInput, zone: &ZoneId) -> PlannerInput {
    let pools: Vec<ResourcePoolStatus> = input
        .nodes
        .iter()
        .enumerate()
        .map(|(index, node)| {
            let limit = if index == 0 { 64 } else { 32 };
            let used = if index == 0 {
                limit
            } else {
                (index % 8) as u16
            };
            ResourcePoolStatus::new(
                format!("rr-work-{index:03}"),
                node.node_id().clone(),
                Some(zone.clone()),
                ResourcePoolClass::RequestResponse,
                limit,
                65_536,
            )
            .with_usage(used, 8_192)
        })
        .collect();
    input.with_resource_pools(pools)
}

fn resource_pool_context(zone: ZoneId) -> PlannerContext {
    PlannerContext::new(resource_pool_connector_id())
        .with_target_zone(zone)
        .with_resource_pool_class(ResourcePoolClass::RequestResponse)
        .with_requested_cpu_cores(4)
        .with_min_memory_mb(2_048)
}

fn bench_resource_pool_placement(c: &mut Criterion) {
    let planner = ExecutionPlanner::new();
    let zone = ZoneId::work();
    let context = resource_pool_context(zone.clone());
    let mut group = c.benchmark_group("resource_pool_placement");

    for &node_count in &[64usize, 256] {
        let default_input = make_resource_pool_input(node_count, &zone);
        let pool_input = attach_resource_pool_state(default_input.clone(), &zone);
        let evidence_connector_id = resource_pool_connector_id();
        let policy = PlacementPolicy::default();

        let default_selected = planner
            .select_best(&default_input, &context)
            .expect("benchmark default placement should select a node");
        assert_eq!(default_selected.node_id.as_str(), "node-000");

        let pooled_plan = planner.plan_with_policy(&pool_input, &context, &policy);
        assert_eq!(
            pooled_plan
                .selected
                .as_ref()
                .map(|node| node.node_id.as_str()),
            Some("node-001")
        );
        let pooled_evidence = planner.evidence_from_plan_with_resource_pools(
            &pooled_plan,
            &pool_input,
            &context,
            &evidence_connector_id,
            None,
        );
        assert_eq!(pooled_evidence.resource_pool_decisions.len(), node_count);
        assert!(
            pooled_evidence
                .resource_pool_decisions
                .iter()
                .any(|decision| !decision.admitted && decision.node_id.as_str() == "node-000")
        );

        group.throughput(Throughput::Elements(node_count as u64));
        group.bench_function(format!("default_{node_count}_nodes"), |b| {
            b.iter(|| {
                let candidates = planner.plan(black_box(&default_input), black_box(&context));
                black_box(
                    candidates
                        .first()
                        .map(|candidate| candidate.node_id.as_str()),
                )
            });
        });
        group.bench_function(format!("pool_aware_evidence_{node_count}_nodes"), |b| {
            b.iter(|| {
                let plan = planner.plan_with_policy(
                    black_box(&pool_input),
                    black_box(&context),
                    black_box(&policy),
                );
                let evidence = planner.evidence_from_plan_with_resource_pools(
                    black_box(&plan),
                    black_box(&pool_input),
                    black_box(&context),
                    black_box(&evidence_connector_id),
                    None,
                );
                black_box((
                    plan.selected.as_ref().map(|node| node.node_id.as_str()),
                    evidence.resource_pool_decisions.len(),
                ))
            });
        });
    }

    group.finish();
}

// ============================================================================
// Session MAC Benchmarks
// ============================================================================

fn bench_session_mac_outgoing(c: &mut Criterion) {
    // Create session with deterministic keys
    let session_id = MeshSessionId([0x42u8; 16]);
    let keys = SessionKeys {
        k_mac_i2r: [0xAB; 32],
        k_mac_r2i: [0xCD; 32],
        k_ctx: [0xEF; 32],
    };
    let mut session = MeshSession::new(
        session_id,
        NodeId::new("node-responder"),
        SessionCryptoSuite::Suite2,
        keys,
        TransportLimits::default(),
        true, // is_initiator
        1_000_000,
        SessionReplayPolicy::default(),
    );

    let frame_data = vec![0xABu8; 1024];

    c.bench_function("session_mac_outgoing_1kb", |b| {
        b.iter(|| {
            let _ = session.mac_outgoing(black_box(&frame_data));
        });
    });
}

fn bench_session_mac_outgoing_large(c: &mut Criterion) {
    let session_id = MeshSessionId([0x42u8; 16]);
    let keys = SessionKeys {
        k_mac_i2r: [0xAB; 32],
        k_mac_r2i: [0xCD; 32],
        k_ctx: [0xEF; 32],
    };
    let mut session = MeshSession::new(
        session_id,
        NodeId::new("node-responder"),
        SessionCryptoSuite::Suite2,
        keys,
        TransportLimits::default(),
        true,
        1_000_000,
        SessionReplayPolicy::default(),
    );

    let frame_data = vec![0xABu8; 65_536]; // 64KB

    let mut group = c.benchmark_group("session_mac");
    group.throughput(Throughput::Bytes(65_536));
    group.bench_function("session_mac_outgoing_64kb", |b| {
        b.iter(|| {
            let _ = session.mac_outgoing(black_box(&frame_data));
        });
    });
    group.finish();
}

fn bench_session_verify_incoming(c: &mut Criterion) {
    let session_id = MeshSessionId([0x42u8; 16]);
    let initiator_keys = SessionKeys {
        k_mac_i2r: [0xAB; 32],
        k_mac_r2i: [0xCD; 32],
        k_ctx: [0xEF; 32],
    };
    let responder_keys = initiator_keys;

    // Create initiator session to generate MAC
    let mut initiator = MeshSession::new(
        session_id,
        NodeId::new("node-responder"),
        SessionCryptoSuite::Suite2,
        initiator_keys,
        TransportLimits::default(),
        true,
        1_000_000,
        SessionReplayPolicy::default(),
    );

    // Create responder session to verify MAC (uses same keys)
    let mut responder = MeshSession::new(
        session_id,
        NodeId::new("node-initiator"),
        SessionCryptoSuite::Suite2,
        responder_keys,
        TransportLimits::default(),
        false, // is_responder
        1_000_000,
        SessionReplayPolicy::default(),
    );

    let frame_data = vec![0xABu8; 1024];

    // Note: This benchmark measures MAC generation + verification together because
    // replay protection requires unique sequence numbers for each verification.
    // The verify_incoming call itself is ~1.5µs; the rest is mac_outgoing overhead.
    c.bench_function("session_mac_roundtrip_1kb", |b| {
        b.iter(|| {
            let (seq, tag) = initiator.mac_outgoing(&frame_data);
            let _ =
                responder.verify_incoming(black_box(seq), black_box(&frame_data), black_box(&tag));
        });
    });
}

// ============================================================================
// Criterion Groups
// ============================================================================

criterion_group!(
    admission_benches,
    bench_admission_check_bytes,
    bench_admission_check_symbols,
    bench_admission_record_bytes,
);

criterion_group!(
    device_benches,
    bench_fitness_score_basic,
    bench_fitness_score_with_gpu,
    bench_fitness_score_with_connector,
    bench_resource_pool_placement,
);

criterion_group!(
    session_benches,
    bench_session_mac_outgoing,
    bench_session_mac_outgoing_large,
    bench_session_verify_incoming,
);

// ============================================================================
// Gossip / XOR Filter / IBLT Benchmarks
// ============================================================================

use fcp_mesh::admission::ObjectAdmissionClass;
use fcp_mesh::{
    gossip::{MeshGossip, XorFilterPlaceholder},
    iblt::Iblt,
};

fn make_object_ids(count: usize) -> Vec<ObjectId> {
    (0..count)
        .map(|i| ObjectId::from_unscoped_bytes(format!("bench-obj-{i}").as_bytes()))
        .collect()
}

fn bench_xor_filter_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("xor_filter_insert");
    for &size in &[1_000usize, 10_000, 100_000] {
        let items: Vec<Vec<u8>> = (0..size)
            .map(|i| format!("item-{i}").into_bytes())
            .collect();
        group.throughput(Throughput::Elements(size as u64));
        group.bench_function(format!("{size}"), |b| {
            b.iter(|| {
                let mut filter = XorFilterPlaceholder::new();
                for item in &items {
                    filter.insert(black_box(item));
                }
                black_box(filter.len())
            });
        });
    }
    group.finish();
}

fn bench_xor_filter_query(c: &mut Criterion) {
    let mut group = c.benchmark_group("xor_filter_query");
    for &size in &[1_000usize, 10_000, 100_000] {
        let items: Vec<Vec<u8>> = (0..size)
            .map(|i| format!("item-{i}").into_bytes())
            .collect();
        let mut filter = XorFilterPlaceholder::new();
        for item in &items {
            filter.insert(item);
        }
        group.throughput(Throughput::Elements(size as u64));
        group.bench_function(format!("{size}"), |b| {
            b.iter(|| {
                let mut hits = 0u32;
                for item in &items {
                    if filter.may_contain(black_box(item)) {
                        hits += 1;
                    }
                }
                black_box(hits)
            });
        });
    }
    group.finish();
}

fn bench_xor_filter_digest(c: &mut Criterion) {
    let mut group = c.benchmark_group("xor_filter_digest");
    for &size in &[1_000usize, 10_000] {
        let mut filter = XorFilterPlaceholder::new();
        for i in 0..size {
            filter.insert(format!("item-{i}").as_bytes());
        }
        group.bench_function(format!("{size}"), |b| {
            b.iter(|| black_box(filter.digest()));
        });
    }
    group.finish();
}

fn bench_iblt_insert_and_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("iblt_reconcile");
    for &diff_size in &[5usize, 20, 50] {
        let shared_ids = make_object_ids(1000);
        let left_only: Vec<ObjectId> = (0..diff_size)
            .map(|i| ObjectId::from_unscoped_bytes(format!("left-only-{i}").as_bytes()))
            .collect();
        let right_only: Vec<ObjectId> = (0..diff_size)
            .map(|i| ObjectId::from_unscoped_bytes(format!("right-only-{i}").as_bytes()))
            .collect();

        group.bench_function(format!("diff_{diff_size}"), |b| {
            b.iter(|| {
                let mut left = Iblt::with_expected_difference(diff_size * 2);
                let mut right = Iblt::with_expected_difference(diff_size * 2);

                for id in &shared_ids {
                    left.insert(*id);
                    right.insert(*id);
                }
                for id in &left_only {
                    left.insert(*id);
                }
                for id in &right_only {
                    right.insert(*id);
                }

                let diff = left.subtract(&right).unwrap();
                let result = diff.decode();
                black_box(result.is_complete())
            });
        });
    }
    group.finish();
}

fn bench_gossip_reconciliation(c: &mut Criterion) {
    let mut group = c.benchmark_group("gossip_reconcile_e2e");
    let zone = fcp_core::ZoneId::work();

    for &shared_count in &[100usize, 1_000, 10_000] {
        let diff_count = 10;
        let shared = make_object_ids(shared_count);
        let a_only: Vec<ObjectId> = (0..diff_count)
            .map(|i| ObjectId::from_unscoped_bytes(format!("a-only-{i}").as_bytes()))
            .collect();
        let b_only: Vec<ObjectId> = (0..diff_count)
            .map(|i| ObjectId::from_unscoped_bytes(format!("b-only-{i}").as_bytes()))
            .collect();

        group.bench_function(format!("shared_{shared_count}_diff_{diff_count}"), |b| {
            b.iter(|| {
                let mut node_a =
                    MeshGossip::with_defaults(fcp_core::TailscaleNodeId::new("bench-a"));
                let mut node_b =
                    MeshGossip::with_defaults(fcp_core::TailscaleNodeId::new("bench-b"));

                for obj in shared.iter().chain(a_only.iter()) {
                    node_a.announce_object(&zone, obj, ObjectAdmissionClass::Admitted, 1);
                }
                for obj in shared.iter().chain(b_only.iter()) {
                    node_b.announce_object(&zone, obj, ObjectAdmissionClass::Admitted, 1);
                }

                let b_iblt = node_b.build_zone_iblt(&zone, diff_count * 2).unwrap();
                let result = node_a.reconcile_zone_iblt(
                    &zone,
                    &fcp_core::TailscaleNodeId::new("bench-b"),
                    &b_iblt,
                    diff_count * 2,
                    2,
                );
                black_box(result.is_some())
            });
        });
    }
    group.finish();
}

criterion_group!(
    gossip_benches,
    bench_xor_filter_insert,
    bench_xor_filter_query,
    bench_xor_filter_digest,
    bench_iblt_insert_and_decode,
    bench_gossip_reconciliation,
);

criterion_main!(
    admission_benches,
    device_benches,
    session_benches,
    gossip_benches,
);
