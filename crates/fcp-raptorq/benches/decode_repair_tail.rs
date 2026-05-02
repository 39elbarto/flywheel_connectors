use std::hint::black_box;
use std::time::Duration;

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use fcp_raptorq::{ObjectTransmissionInformation, RaptorQConfig, RaptorQDecoder, RaptorQEncoder};

fn bench_config() -> RaptorQConfig {
    RaptorQConfig {
        symbol_size: 64,
        repair_ratio_bps: 10_000,
        max_object_size: 8 * 1024 * 1024,
        decode_timeout: Duration::from_secs(30),
        max_chunk_threshold: 256 * 1024,
        chunk_size: 64 * 1024,
    }
}

fn deterministic_payload(symbols: usize, symbol_size: usize) -> Vec<u8> {
    let len = symbols
        .checked_mul(symbol_size)
        .expect("bench payload size fits usize");
    (0..len)
        .map(|index| u8::try_from(index % 251).expect("payload byte fits u8"))
        .collect()
}

fn repair_tail_workload(
    source_symbols: usize,
) -> (
    RaptorQConfig,
    ObjectTransmissionInformation,
    Vec<(u32, Vec<u8>)>,
) {
    let config = bench_config();
    let payload = deterministic_payload(source_symbols, usize::from(config.symbol_size));
    let encoder = RaptorQEncoder::new(&payload, &config).expect("bench payload encodes");
    let symbols = encoder.encode_all();
    let oti = encoder.transmission_info().with_payload_hash([0xA5; 32]);
    (config, oti, symbols)
}

fn bench_decode_repair_tail(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_repair_tail_wrong_hash");

    for source_symbols in [16_usize, 32, 64] {
        let (_, _, symbols) = repair_tail_workload(source_symbols);
        group.throughput(Throughput::Elements(
            u64::try_from(symbols.len()).expect("bench symbol count fits u64"),
        ));
        group.bench_with_input(
            BenchmarkId::from_parameter(source_symbols),
            &source_symbols,
            |b, &source_symbols| {
                b.iter_batched(
                    || repair_tail_workload(source_symbols),
                    |(config, oti, symbols)| {
                        let mut decoder = RaptorQDecoder::new(oti, &config);
                        for (esi, data) in symbols {
                            let _ = decoder
                                .add_symbol(esi, data)
                                .expect("wrong hash decode remains retryable");
                        }
                        black_box(decoder.received_count())
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_millis(100))
        .measurement_time(Duration::from_millis(500));
    targets = bench_decode_repair_tail
}
criterion_main!(benches);
