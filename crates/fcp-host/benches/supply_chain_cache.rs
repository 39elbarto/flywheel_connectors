//! Raw-sample microbenchmark for the supply-chain verification cache.
//!
//! Run with:
//! `FCP_SUPPLY_CHAIN_CACHE_BENCH_OUT=/tmp/supply-chain-cache.json cargo bench -p fcp-host --bench supply_chain_cache`

use std::collections::HashMap;
use std::hint::black_box;
use std::path::PathBuf;
use std::time::Instant;

use fcp_host::S3FifoCache;
use serde::Serialize;

const CAPACITY: usize = 4_096;
const HOT_KEYS: usize = 256;
const SAMPLES: usize = 12_000;
const ADMISSION_INTERVAL: usize = 5;

#[derive(Clone, Copy)]
struct BenchValue(u64);

enum Operation {
    Lookup(String),
    Admit(String),
}

trait CacheBench {
    fn get(&mut self, key: &str) -> Option<BenchValue>;
    fn insert(&mut self, key: String, value: BenchValue);
    fn len(&self) -> usize;
}

struct LegacyOldestCache {
    capacity: usize,
    tick: u64,
    entries: HashMap<String, (BenchValue, u64)>,
}

impl LegacyOldestCache {
    fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            tick: 0,
            entries: HashMap::new(),
        }
    }
}

impl CacheBench for LegacyOldestCache {
    fn get(&mut self, key: &str) -> Option<BenchValue> {
        self.entries.get(key).map(|(value, _)| *value)
    }

    fn insert(&mut self, key: String, value: BenchValue) {
        if let Some(entry) = self.entries.get_mut(&key) {
            *entry = (value, self.tick);
            self.tick = self.tick.saturating_add(1);
            return;
        }

        if self.entries.len() >= self.capacity {
            let oldest_key = self
                .entries
                .iter()
                .min_by_key(|(_, (_, inserted_at))| *inserted_at)
                .map(|(key, _)| key.clone());
            if let Some(oldest_key) = oldest_key {
                self.entries.remove(&oldest_key);
            }
        }

        self.entries.insert(key, (value, self.tick));
        self.tick = self.tick.saturating_add(1);
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

impl CacheBench for S3FifoCache<BenchValue> {
    fn get(&mut self, key: &str) -> Option<BenchValue> {
        S3FifoCache::get(self, key)
    }

    fn insert(&mut self, key: String, value: BenchValue) {
        S3FifoCache::insert(self, key, value);
    }

    fn len(&self) -> usize {
        S3FifoCache::len(self)
    }
}

#[derive(Serialize)]
struct RunReport {
    implementation: &'static str,
    sample_count: usize,
    p50_ns: u64,
    p99_ns: u64,
    p999_ns: u64,
    max_ns: u64,
    hits: usize,
    misses: usize,
    admissions: usize,
    final_len: usize,
    raw_samples_ns: Vec<u64>,
}

impl RunReport {
    fn summary(&self) -> RunSummary {
        RunSummary {
            implementation: self.implementation,
            sample_count: self.sample_count,
            p50_ns: self.p50_ns,
            p99_ns: self.p99_ns,
            p999_ns: self.p999_ns,
            max_ns: self.max_ns,
            hits: self.hits,
            misses: self.misses,
            admissions: self.admissions,
            final_len: self.final_len,
        }
    }
}

#[derive(Serialize)]
struct RunSummary {
    implementation: &'static str,
    sample_count: usize,
    p50_ns: u64,
    p99_ns: u64,
    p999_ns: u64,
    max_ns: u64,
    hits: usize,
    misses: usize,
    admissions: usize,
    final_len: usize,
}

#[derive(Serialize)]
struct BenchReport {
    benchmark: &'static str,
    technique: &'static str,
    capacity: usize,
    hot_keys: usize,
    admission_interval: usize,
    legacy_oldest_scan: RunReport,
    s3_fifo: RunReport,
}

#[derive(Serialize)]
struct BenchSummary {
    benchmark: &'static str,
    technique: &'static str,
    capacity: usize,
    hot_keys: usize,
    admission_interval: usize,
    legacy_oldest_scan: RunSummary,
    s3_fifo: RunSummary,
    raw_samples_artifact: Option<String>,
}

fn key(prefix: &str, index: usize) -> String {
    format!("{prefix}-{index:05}")
}

fn operations() -> Vec<Operation> {
    let mut operations = Vec::with_capacity(SAMPLES);
    for index in 0..SAMPLES {
        if index % ADMISSION_INTERVAL == 0 {
            operations.push(Operation::Admit(key("admit", index)));
        } else {
            operations.push(Operation::Lookup(key("hot", index % HOT_KEYS)));
        }
    }
    operations
}

fn warm_cache<C: CacheBench>(cache: &mut C) {
    for index in 0..HOT_KEYS {
        cache.insert(
            key("hot", index),
            BenchValue(u64::try_from(index).unwrap_or(u64::MAX)),
        );
    }
    for index in HOT_KEYS..CAPACITY {
        cache.insert(
            key("filler", index),
            BenchValue(u64::try_from(index).unwrap_or(u64::MAX)),
        );
    }
    for index in 0..HOT_KEYS {
        let value = cache.get(&key("hot", index));
        black_box(value.map(|value| value.0));
    }
}

fn elapsed_ns(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn percentile(sorted_samples: &[u64], per_mille: usize) -> u64 {
    assert!(
        !sorted_samples.is_empty(),
        "benchmark report requires at least one sample"
    );
    let rank = sorted_samples
        .len()
        .saturating_mul(per_mille)
        .div_ceil(1_000);
    sorted_samples[rank.saturating_sub(1).min(sorted_samples.len() - 1)]
}

fn run<C: CacheBench>(
    implementation: &'static str,
    mut cache: C,
    operations: &[Operation],
) -> RunReport {
    warm_cache(&mut cache);

    let mut samples = Vec::with_capacity(operations.len());
    let mut hits = 0_usize;
    let mut misses = 0_usize;
    let mut admissions = 0_usize;

    for (index, operation) in operations.iter().enumerate() {
        match operation {
            Operation::Lookup(key) => {
                let start = Instant::now();
                let value = cache.get(key);
                samples.push(elapsed_ns(start));
                match value {
                    Some(value) => {
                        hits += 1;
                        black_box(value.0);
                    }
                    None => misses += 1,
                }
            }
            Operation::Admit(key) => {
                let start = Instant::now();
                cache.insert(
                    key.clone(),
                    BenchValue(u64::try_from(index).unwrap_or(u64::MAX)),
                );
                samples.push(elapsed_ns(start));
                admissions += 1;
            }
        }
    }

    let mut sorted = samples.clone();
    sorted.sort_unstable();

    RunReport {
        implementation,
        sample_count: samples.len(),
        p50_ns: percentile(&sorted, 500),
        p99_ns: percentile(&sorted, 990),
        p999_ns: percentile(&sorted, 999),
        max_ns: sorted.last().copied().unwrap_or(0),
        hits,
        misses,
        admissions,
        final_len: cache.len(),
        raw_samples_ns: samples,
    }
}

fn write_report_if_requested(json: &str) -> Option<String> {
    let Ok(path) = std::env::var("FCP_SUPPLY_CHAIN_CACHE_BENCH_OUT") else {
        return None;
    };
    let path = PathBuf::from(path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create benchmark output directory");
    }
    std::fs::write(&path, json).expect("write benchmark report");
    eprintln!("wrote benchmark report to {}", path.display());
    Some(path.display().to_string())
}

fn main() {
    let operations = operations();
    let legacy_oldest_scan = run(
        "legacy_oldest_scan",
        LegacyOldestCache::new(CAPACITY),
        &operations,
    );
    let s3_fifo = run("s3_fifo", S3FifoCache::new(CAPACITY), &operations);

    assert!(
        s3_fifo.hits >= legacy_oldest_scan.hits,
        "S3-FIFO must preserve at least as many hot-key hits as legacy scan: legacy={} s3={}",
        legacy_oldest_scan.hits,
        s3_fifo.hits
    );
    assert!(
        s3_fifo.p99_ns < legacy_oldest_scan.p99_ns,
        "S3-FIFO p99 must beat legacy scan: legacy={}ns s3={}ns",
        legacy_oldest_scan.p99_ns,
        s3_fifo.p99_ns
    );
    assert!(
        s3_fifo.p999_ns < legacy_oldest_scan.p999_ns,
        "S3-FIFO p999 must beat legacy scan: legacy={}ns s3={}ns",
        legacy_oldest_scan.p999_ns,
        s3_fifo.p999_ns
    );

    let report = BenchReport {
        benchmark: "supply_chain_cache_raw_samples",
        technique: "s3_fifo",
        capacity: CAPACITY,
        hot_keys: HOT_KEYS,
        admission_interval: ADMISSION_INTERVAL,
        legacy_oldest_scan,
        s3_fifo,
    };
    let json = serde_json::to_string_pretty(&report).expect("serialize benchmark report");
    let raw_samples_artifact = write_report_if_requested(&json);
    let summary = BenchSummary {
        benchmark: report.benchmark,
        technique: report.technique,
        capacity: report.capacity,
        hot_keys: report.hot_keys,
        admission_interval: report.admission_interval,
        legacy_oldest_scan: report.legacy_oldest_scan.summary(),
        s3_fifo: report.s3_fifo.summary(),
        raw_samples_artifact,
    };
    let summary_json = serde_json::to_string_pretty(&summary).expect("serialize benchmark summary");
    println!("{summary_json}");
}
