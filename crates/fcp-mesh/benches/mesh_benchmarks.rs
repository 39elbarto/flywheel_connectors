//! Benchmarks for fcp-mesh hot paths.
//!
//! These benchmarks verify performance of the critical mesh operations:
//! - Admission control checks (every incoming request)
//! - Device fitness calculation (execution planning)
//! - Session MAC operations (authenticate each frame)

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use fcp_core::{ConnectorId, ObjectId};
use fcp_mesh::{
    admission::{AdmissionController, AdmissionPolicy},
    device::{
        CpuArch, DeviceProfile, FitnessContext, FitnessScore, GpuProfile, GpuVendor,
        InstalledConnector, PowerSource,
    },
    session::MeshSession,
};
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
);

criterion_group!(
    session_benches,
    bench_session_mac_outgoing,
    bench_session_mac_outgoing_large,
    bench_session_verify_incoming,
);

criterion_main!(admission_benches, device_benches, session_benches,);
