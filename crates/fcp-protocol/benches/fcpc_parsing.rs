//! Benchmarks for FCPC frame parsing hot paths.
//!
//! These benchmarks measure the performance of FCPC frame encoding/decoding
//! and AEAD seal/open operations as required by the FCP2 control plane.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

use fcp_protocol::{
    FCPC_HEADER_LEN, FCPC_TAG_LEN, FcpcFrame, FcpcFrameFlags, FcpcFrameHeader, MeshSessionId,
    SessionDirection,
};

/// Test session ID for benchmarking.
const SESSION_ID_BYTES: [u8; 16] = [0xAA; 16];

/// Test encryption key for benchmarking.
const K_CTX: [u8; 32] = [0x11; 32];

/// Test direction for benchmarking.
const DIR: SessionDirection = SessionDirection::InitiatorToResponder;

/// Build a test header for benchmarking.
const fn test_header(payload_len: u32) -> FcpcFrameHeader {
    FcpcFrameHeader {
        version: 1,
        session_id: MeshSessionId(SESSION_ID_BYTES),
        seq: 42,
        flags: FcpcFrameFlags::ENCRYPTED,
        len: payload_len,
    }
}

fn bench_header_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("fcpc_header_encode");
    group.throughput(Throughput::Bytes(FCPC_HEADER_LEN as u64));

    group.bench_function("36_bytes", |b| {
        let header = test_header(1024);
        b.iter(|| black_box(header.encode()));
    });

    group.finish();
}

fn bench_header_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("fcpc_header_decode");
    group.throughput(Throughput::Bytes(FCPC_HEADER_LEN as u64));

    let header = test_header(1024);
    let encoded = header.encode();

    group.bench_function("36_bytes", |b| {
        b.iter(|| black_box(FcpcFrameHeader::decode(&encoded)));
    });

    group.finish();
}

fn bench_frame_seal(c: &mut Criterion) {
    let mut group = c.benchmark_group("fcpc_frame_seal");
    let session_id = MeshSessionId(SESSION_ID_BYTES);

    for payload_size in [64, 256, 1024, 4096] {
        let plaintext = vec![0xBB_u8; payload_size];
        let total_size = FCPC_HEADER_LEN + payload_size + FCPC_TAG_LEN;
        group.throughput(Throughput::Bytes(total_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(payload_size),
            &payload_size,
            |b, _| {
                b.iter(|| {
                    black_box(FcpcFrame::seal(
                        session_id,
                        42,
                        DIR,
                        FcpcFrameFlags::default(),
                        &plaintext,
                        &K_CTX,
                    ))
                });
            },
        );
    }

    group.finish();
}

fn bench_frame_open(c: &mut Criterion) {
    let mut group = c.benchmark_group("fcpc_frame_open");
    let session_id = MeshSessionId(SESSION_ID_BYTES);

    for payload_size in [64, 256, 1024, 4096] {
        let plaintext = vec![0xBB_u8; payload_size];
        let frame = FcpcFrame::seal(
            session_id,
            42,
            DIR,
            FcpcFrameFlags::default(),
            &plaintext,
            &K_CTX,
        )
        .expect("seal should succeed");
        let total_size = FCPC_HEADER_LEN + payload_size + FCPC_TAG_LEN;
        group.throughput(Throughput::Bytes(total_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(payload_size),
            &payload_size,
            |b, _| {
                b.iter(|| black_box(frame.open(DIR, &K_CTX)));
            },
        );
    }

    group.finish();
}

fn bench_frame_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("fcpc_frame_encode");
    let session_id = MeshSessionId(SESSION_ID_BYTES);

    for payload_size in [64, 256, 1024, 4096] {
        let plaintext = vec![0xBB_u8; payload_size];
        let frame = FcpcFrame::seal(
            session_id,
            42,
            DIR,
            FcpcFrameFlags::default(),
            &plaintext,
            &K_CTX,
        )
        .expect("seal should succeed");
        let total_size = FCPC_HEADER_LEN + payload_size + FCPC_TAG_LEN;
        group.throughput(Throughput::Bytes(total_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(payload_size),
            &payload_size,
            |b, _| {
                b.iter(|| black_box(frame.encode()));
            },
        );
    }

    group.finish();
}

fn bench_frame_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("fcpc_frame_decode");
    let session_id = MeshSessionId(SESSION_ID_BYTES);

    for payload_size in [64, 256, 1024, 4096] {
        let plaintext = vec![0xBB_u8; payload_size];
        let frame = FcpcFrame::seal(
            session_id,
            42,
            DIR,
            FcpcFrameFlags::default(),
            &plaintext,
            &K_CTX,
        )
        .expect("seal should succeed");
        let encoded = frame.encode();
        group.throughput(Throughput::Bytes(encoded.len() as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(payload_size),
            &payload_size,
            |b, _| {
                b.iter(|| black_box(FcpcFrame::decode(&encoded)));
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_header_encode,
    bench_header_decode,
    bench_frame_seal,
    bench_frame_open,
    bench_frame_encode,
    bench_frame_decode,
);
criterion_main!(benches);
