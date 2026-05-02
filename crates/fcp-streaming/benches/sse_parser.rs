use std::fmt::Write as _;
use std::hint::black_box;
use std::time::Duration;

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use fcp_streaming::__bench::SseParserBenchHarness;

const MAX_DATA_BYTES: usize = 2 * 1024 * 1024;
const NEXT_CHUNK: &[u8] = b"x";
const RETAINED_SIZES: [(&str, usize); 3] =
    [("1kb", 1024), ("64kb", 64 * 1024), ("1mb", 1024 * 1024)];

fn many_small_events_chunk(event_count: usize) -> Vec<u8> {
    let mut chunk = String::new();
    for index in 0..event_count {
        writeln!(&mut chunk, "data: event-{index}").expect("write to string");
        chunk.push('\n');
    }
    chunk.into_bytes()
}

fn multi_data_line_event(line_count: usize) -> Vec<u8> {
    let mut chunk = String::new();
    for index in 0..line_count {
        writeln!(&mut chunk, "data: line-{index}").expect("write to string");
    }
    chunk.push('\n');
    chunk.into_bytes()
}

fn bench_retained_long_line_next_chunk(c: &mut Criterion) {
    let mut group = c.benchmark_group("sse_parser_retained_long_line_next_chunk");
    for (label, retained_size) in RETAINED_SIZES {
        group.throughput(Throughput::Bytes(
            u64::try_from(retained_size + NEXT_CHUNK.len()).expect("size fits u64"),
        ));
        group.bench_with_input(
            BenchmarkId::from_parameter(label),
            &retained_size,
            |b, &retained_size| {
                b.iter_batched(
                    || {
                        SseParserBenchHarness::with_retained_long_line(
                            retained_size,
                            MAX_DATA_BYTES,
                        )
                    },
                    |mut parser| {
                        let events = parser.parse_chunk(black_box(NEXT_CHUNK));
                        black_box((events.len(), parser.retained_bytes(), parser.parse_cursor()));
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_many_small_events(c: &mut Criterion) {
    let event_count = 256_usize;
    let chunk = many_small_events_chunk(event_count);
    let mut group = c.benchmark_group("sse_parser_many_small_events");
    group.throughput(Throughput::Elements(
        u64::try_from(event_count).expect("event count fits u64"),
    ));
    group.bench_function(BenchmarkId::from_parameter(event_count), |b| {
        b.iter_batched(
            || (SseParserBenchHarness::empty(MAX_DATA_BYTES), chunk.clone()),
            |(mut parser, chunk)| {
                let events = parser.parse_chunk(black_box(chunk.as_slice()));
                black_box(events.len());
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn bench_multi_data_line_event(c: &mut Criterion) {
    let line_count = 128_usize;
    let chunk = multi_data_line_event(line_count);
    let mut group = c.benchmark_group("sse_parser_multi_data_line_event");
    group.throughput(Throughput::Elements(
        u64::try_from(line_count).expect("line count fits u64"),
    ));
    group.bench_function(BenchmarkId::from_parameter(line_count), |b| {
        b.iter_batched(
            || (SseParserBenchHarness::empty(MAX_DATA_BYTES), chunk.clone()),
            |(mut parser, chunk)| {
                let events = parser.parse_chunk(black_box(chunk.as_slice()));
                black_box(events.len());
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_millis(100))
        .measurement_time(Duration::from_millis(500));
    targets =
        bench_retained_long_line_next_chunk,
        bench_many_small_events,
        bench_multi_data_line_event
}
criterion_main!(benches);
