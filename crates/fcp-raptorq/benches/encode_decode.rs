use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use fcp_raptorq::{ObjectTransmissionInformation, RaptorQConfig, RaptorQDecoder, RaptorQEncoder};

const FULL_ENCODE_CASES: [(usize, u16); 5] = [
    (64 * 1024, 1024),
    (64 * 1024, 4096),
    (1024 * 1024, 1024),
    (1024 * 1024, 4096),
    (16 * 1024 * 1024, 4096),
];

#[derive(Clone, Copy)]
enum DecodeCase {
    ExactK,
    KPlusOne,
    Loss10Pct,
    DenseFallback,
}

impl DecodeCase {
    const ALL: [Self; 4] = [
        Self::ExactK,
        Self::KPlusOne,
        Self::Loss10Pct,
        Self::DenseFallback,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::ExactK => "exact_k",
            Self::KPlusOne => "k_plus_one",
            Self::Loss10Pct => "loss_10pct",
            Self::DenseFallback => "dense_fallback",
        }
    }
}

fn config(symbol_size: u16) -> RaptorQConfig {
    RaptorQConfig {
        symbol_size,
        repair_ratio_bps: 2_500,
        max_object_size: 32 * 1024 * 1024,
        decode_timeout: Duration::from_secs(30),
        max_chunk_threshold: 256 * 1024,
        chunk_size: 1024 * 1024,
    }
}

fn deterministic_payload(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| u8::try_from((index.wrapping_mul(31).wrapping_add(7)) % 251).unwrap_or(0))
        .collect()
}

fn encoded_workload(
    payload_len: usize,
    symbol_size: u16,
) -> (
    RaptorQConfig,
    ObjectTransmissionInformation,
    Vec<(u32, Vec<u8>)>,
) {
    let config = config(symbol_size);
    let payload = deterministic_payload(payload_len);
    let encoder = RaptorQEncoder::new(&payload, &config).expect("benchmark payload encodes");
    let oti = encoder.transmission_info();
    let symbols = encoder.into_encode_all();
    (config, oti, symbols)
}

fn selected_decode_symbols(
    case: DecodeCase,
    k: usize,
    symbols: &[(u32, Vec<u8>)],
) -> Vec<(u32, Vec<u8>)> {
    let source = &symbols[..k];
    let repair = &symbols[k..];

    match case {
        DecodeCase::ExactK => source.to_vec(),
        DecodeCase::KPlusOne => source
            .iter()
            .chain(repair.iter().take(1))
            .cloned()
            .collect(),
        DecodeCase::Loss10Pct => {
            let lost = k.div_ceil(10).max(1);
            source
                .iter()
                .enumerate()
                .filter(|(index, _)| index % 10 != 0)
                .map(|(_, symbol)| symbol.clone())
                .chain(repair.iter().take(lost.saturating_add(4)).cloned())
                .collect()
        }
        DecodeCase::DenseFallback => {
            let lost = k.div_ceil(4).max(1);
            source
                .iter()
                .enumerate()
                .filter(|(index, _)| index % 4 != 0)
                .map(|(_, symbol)| symbol.clone())
                .chain(repair.iter().take(lost.saturating_add(8)).cloned())
                .collect()
        }
    }
}

fn decode_symbols(
    config: &RaptorQConfig,
    oti: ObjectTransmissionInformation,
    symbols: &[(u32, Vec<u8>)],
) -> usize {
    let mut decoder = RaptorQDecoder::new(oti, config);
    let mut decoded_len = 0;
    for (esi, data) in symbols {
        if let Some(payload) = decoder
            .add_symbol(*esi, data.clone())
            .expect("benchmark symbols decode without hard errors")
        {
            decoded_len = payload.len();
        }
    }
    decoded_len
}

fn bench_encoder_new(c: &mut Criterion) {
    let mut group = c.benchmark_group("raptorq_encoder_new");
    for (payload_len, symbol_size) in FULL_ENCODE_CASES {
        let payload = deterministic_payload(payload_len);
        let config = config(symbol_size);
        group.throughput(Throughput::Bytes(
            u64::try_from(payload_len).unwrap_or(u64::MAX),
        ));

        group.bench_function(
            BenchmarkId::new(
                "chunk_and_index",
                format!("{payload_len}_bytes_{symbol_size}_sym"),
            ),
            |b| {
                b.iter(|| {
                    std::hint::black_box(
                        RaptorQEncoder::new(&payload, &config).expect("payload encodes"),
                    );
                });
            },
        );
    }
    group.finish();
}

fn bench_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("raptorq_encode");
    for (payload_len, symbol_size) in FULL_ENCODE_CASES {
        let payload = deterministic_payload(payload_len);
        let config = config(symbol_size);
        group.throughput(Throughput::Bytes(
            u64::try_from(payload_len).unwrap_or(u64::MAX),
        ));

        group.bench_function(
            BenchmarkId::new(
                "encode_all",
                format!("{payload_len}_bytes_{symbol_size}_sym"),
            ),
            |b| {
                b.iter(|| {
                    let encoder = RaptorQEncoder::new(&payload, &config).expect("payload encodes");
                    std::hint::black_box(encoder.encode_all());
                });
            },
        );
        group.bench_function(
            BenchmarkId::new(
                "into_encode_all",
                format!("{payload_len}_bytes_{symbol_size}_sym"),
            ),
            |b| {
                b.iter(|| {
                    let encoder = RaptorQEncoder::new(&payload, &config).expect("payload encodes");
                    std::hint::black_box(encoder.into_encode_all());
                });
            },
        );
    }
    group.finish();
}

fn decode_cases_for(payload_len: usize, symbol_size: u16) -> &'static [DecodeCase] {
    let source_symbols = payload_len.div_ceil(usize::from(symbol_size));
    if source_symbols > 256 {
        &[DecodeCase::ExactK, DecodeCase::KPlusOne]
    } else {
        &DecodeCase::ALL
    }
}

fn bench_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("raptorq_decode");
    for (payload_len, symbol_size) in FULL_ENCODE_CASES {
        let (config, oti, symbols) = encoded_workload(payload_len, symbol_size);
        let k = payload_len.div_ceil(usize::from(symbol_size));
        group.throughput(Throughput::Bytes(
            u64::try_from(payload_len).unwrap_or(u64::MAX),
        ));

        for case in decode_cases_for(payload_len, symbol_size) {
            let selected = selected_decode_symbols(*case, k, &symbols);
            group.bench_function(
                BenchmarkId::new(
                    case.label(),
                    format!("{payload_len}_bytes_{symbol_size}_sym"),
                ),
                |b| {
                    b.iter(|| {
                        let decoded_len = decode_symbols(&config, oti, &selected);
                        assert_eq!(decoded_len, payload_len);
                        std::hint::black_box(decoded_len);
                    });
                },
            );
        }
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_millis(100))
        .measurement_time(Duration::from_millis(300));
    targets = bench_encoder_new, bench_encode, bench_decode
}
criterion_main!(benches);
