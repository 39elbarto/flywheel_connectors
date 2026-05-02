//! Benchmarks for FCPS frame parsing hot paths.
//!
//! These benchmarks measure the performance of FCPS frame encoding/decoding
//! as required by the FCP2 data plane acceptance criteria.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

use fcp_prelude::{ObjectId, ZoneIdHash, ZoneKeyId};
use fcp_protocol::{
    FCPS_HEADER_LEN, FcpsDatagram, FcpsFrame, FcpsFrameHeader, FcpsFrameRefs, FrameFlags,
    MeshSessionId, SYMBOL_RECORD_OVERHEAD, SymbolRecord,
};

/// Build a test header for benchmarking.
fn test_header(symbol_count: u32, symbol_size: u16) -> FcpsFrameHeader {
    let payload_len = symbol_count as usize * (SYMBOL_RECORD_OVERHEAD + symbol_size as usize);
    let payload_len_u32 = u32::try_from(payload_len).expect("payload length fits in u32");
    FcpsFrameHeader {
        version: 1,
        flags: FrameFlags::ENCRYPTED | FrameFlags::RAPTORQ,
        symbol_count,
        total_payload_len: payload_len_u32,
        object_id: ObjectId::from_bytes([0x11; 32]),
        symbol_size,
        zone_key_id: ZoneKeyId::from_bytes([0x22; 8]),
        zone_id_hash: ZoneIdHash::from_bytes([0x33; 32]),
        epoch_id: 1000,
        sender_instance_id: 0xDEAD_BEEF,
        frame_seq: 42,
    }
}

/// Build a test symbol record for benchmarking.
fn test_symbol(esi: u32, symbol_size: u16) -> SymbolRecord {
    SymbolRecord {
        esi,
        k: 10,
        data: vec![0xAA; symbol_size as usize],
        auth_tag: [0xBB; 16],
    }
}

/// Build a test frame for benchmarking.
fn test_frame(symbol_count: u32, symbol_size: u16) -> FcpsFrame {
    let header = test_header(symbol_count, symbol_size);
    let symbols = (0..symbol_count)
        .map(|esi| test_symbol(esi, symbol_size))
        .collect();
    FcpsFrame { header, symbols }
}

/// Build a test datagram for benchmarking.
fn test_datagram(frame_bytes_len: usize) -> FcpsDatagram {
    FcpsDatagram {
        session_id: MeshSessionId([0x42; 16]),
        seq: 12345,
        mac: [0xCC; 16],
        frame_bytes: vec![0xDD; frame_bytes_len],
    }
}

fn bench_header_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("fcps_header_encode");
    group.throughput(Throughput::Bytes(FCPS_HEADER_LEN as u64));

    group.bench_function("114_bytes", |b| {
        let header = test_header(10, 1024);
        b.iter(|| black_box(header.encode()));
    });

    group.finish();
}

fn bench_header_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("fcps_header_decode");
    group.throughput(Throughput::Bytes(FCPS_HEADER_LEN as u64));

    let header = test_header(10, 1024);
    let encoded = header.encode();

    group.bench_function("114_bytes", |b| {
        b.iter(|| black_box(FcpsFrameHeader::decode(&encoded)));
    });

    group.finish();
}

fn bench_symbol_record_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("fcps_symbol_encode");

    for symbol_size in [64u16, 256, 1024] {
        let wire_size = SYMBOL_RECORD_OVERHEAD + symbol_size as usize;
        group.throughput(Throughput::Bytes(wire_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(symbol_size),
            &symbol_size,
            |b, &size| {
                let record = test_symbol(0, size);
                b.iter(|| black_box(record.encode()));
            },
        );
    }

    group.finish();
}

fn bench_symbol_record_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("fcps_symbol_decode");

    for symbol_size in [64u16, 256, 1024] {
        let record = test_symbol(0, symbol_size);
        let encoded = record.encode();
        let wire_size = SYMBOL_RECORD_OVERHEAD + symbol_size as usize;
        group.throughput(Throughput::Bytes(wire_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(symbol_size),
            &symbol_size,
            |b, &size| {
                b.iter(|| black_box(SymbolRecord::decode(&encoded, size)));
            },
        );
    }

    group.finish();
}

fn bench_frame_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("fcps_frame_encode");

    for (symbol_count, symbol_size) in [(1, 1024), (10, 1024), (64, 256)] {
        let frame = test_frame(symbol_count, symbol_size);
        let frame_size = FCPS_HEADER_LEN
            + symbol_count as usize * (SYMBOL_RECORD_OVERHEAD + symbol_size as usize);
        group.throughput(Throughput::Bytes(frame_size as u64));
        group.bench_with_input(
            BenchmarkId::new("symbols_x_size", format!("{symbol_count}x{symbol_size}")),
            &(symbol_count, symbol_size),
            |b, _| {
                b.iter(|| black_box(frame.encode().expect("encode")));
            },
        );
    }

    group.finish();
}

fn bench_frame_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("fcps_frame_decode");

    for (symbol_count, symbol_size) in [(1, 1024), (10, 1024), (64, 256)] {
        let frame = test_frame(symbol_count, symbol_size);
        let encoded = frame.encode().expect("encode");
        let frame_size = encoded.len();
        group.throughput(Throughput::Bytes(frame_size as u64));
        group.bench_with_input(
            BenchmarkId::new("symbols_x_size", format!("{symbol_count}x{symbol_size}")),
            &(symbol_count, symbol_size),
            |b, _| {
                b.iter(|| black_box(FcpsFrame::decode(&encoded, 65536)));
            },
        );
    }

    group.finish();
}

fn bench_frame_decode_refs(c: &mut Criterion) {
    let mut group = c.benchmark_group("fcps_frame_decode_refs");

    for (symbol_count, symbol_size) in [(1, 1024), (10, 1024), (64, 256)] {
        let frame = test_frame(symbol_count, symbol_size);
        let encoded = frame.encode().expect("encode");
        let frame_size = encoded.len();
        group.throughput(Throughput::Bytes(frame_size as u64));
        group.bench_with_input(
            BenchmarkId::new("symbols_x_size", format!("{symbol_count}x{symbol_size}")),
            &(symbol_count, symbol_size),
            |b, _| {
                b.iter(|| black_box(FcpsFrameRefs::decode(&encoded, 65536)));
            },
        );
    }

    group.finish();
}

fn bench_datagram_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("fcps_datagram_encode");

    for frame_size in [100, 500, 1400] {
        let datagram = test_datagram(frame_size);
        let total_size = 16 + 8 + 16 + frame_size; // session_id + seq + mac + frame_bytes
        group.throughput(Throughput::Bytes(total_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(frame_size),
            &frame_size,
            |b, _| {
                b.iter(|| black_box(datagram.encode()));
            },
        );
    }

    group.finish();
}

fn bench_datagram_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("fcps_datagram_decode");

    for frame_size in [100, 500, 1400] {
        let datagram = test_datagram(frame_size);
        let encoded = datagram.encode();
        group.throughput(Throughput::Bytes(encoded.len() as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(frame_size),
            &frame_size,
            |b, _| {
                b.iter(|| black_box(FcpsDatagram::decode(&encoded, 1500)));
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_header_encode,
    bench_header_decode,
    bench_symbol_record_encode,
    bench_symbol_record_decode,
    bench_frame_encode,
    bench_frame_decode,
    bench_frame_decode_refs,
    bench_datagram_encode,
    bench_datagram_decode,
);
criterion_main!(benches);
