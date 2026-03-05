//! FCP2 performance benchmark suite.
//!
//! This module implements the `fcp bench` command with subcommands for various
//! benchmark targets. All benchmarks emit machine-readable JSON output with
//! environment metadata for regression tracking.
//!
//! ## Canonical Targets (README-aligned)
//!
//! - Cold start (connector activate): p50 < 100ms / p99 < 500ms
//! - Local invoke latency (same node): p50 < 2ms / p99 < 10ms
//! - Tailnet invoke latency (LAN/direct): p50 < 20ms / p99 < 100ms
//! - Tailnet invoke latency (DERP): p50 < 150ms / p99 < 500ms
//! - Symbol reconstruction (1MB): p50 < 50ms / p99 < 250ms
//! - Secret reconstruction (k-of-n): p50 < 150ms / p99 < 750ms
//! - Memory overhead: < 10MB per connector (idle)
//! - CPU overhead: < 1% idle (event-driven)
//! - Binary size: < 20MB compressed

mod cbor;
mod environment;
mod runner;
mod types;

pub use types::{BenchmarkReport, BenchmarkResult};

use anyhow::{anyhow, bail};
use clap::{Args, Subcommand};

/// Arguments for the `fcp bench` command.
#[derive(Args)]
pub struct BenchArgs {
    #[command(subcommand)]
    command: BenchCommand,

    /// Output format: json (machine-readable) or human (pretty-printed).
    #[arg(long, default_value = "json")]
    format: OutputFormat,

    /// Number of iterations for each benchmark.
    #[arg(long, default_value = "100")]
    iterations: u32,

    /// Number of warmup iterations before measurement.
    #[arg(long, default_value = "10")]
    warmup: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum OutputFormat {
    Json,
    Human,
}

#[derive(Subcommand)]
enum BenchCommand {
    /// Benchmark connector cold start time.
    ///
    /// Target: p50 < 100ms / p99 < 500ms (stretch goal: p50 < 50ms)
    ConnectorActivate {
        /// Path to connector binary.
        #[arg(long)]
        connector: Option<String>,
    },

    /// Benchmark local invoke latency (same node).
    ///
    /// Target: p50 < 2ms / p99 < 10ms
    InvokeLocal,

    /// Benchmark mesh invoke latency.
    ///
    /// Target (direct/LAN): p50 < 20ms / p99 < 100ms
    /// Target (DERP): p50 < 150ms / p99 < 500ms
    InvokeMesh {
        /// Network path: direct (LAN) or derp (relay).
        #[arg(long)]
        path: MeshPath,
    },

    /// Benchmark `RaptorQ` symbol encoding/decoding.
    ///
    /// Target (1MB): p50 < 50ms / p99 < 250ms
    Raptorq {
        /// Payload size (e.g., "1mb", "100kb").
        #[arg(long, default_value = "1mb")]
        size: String,
    },

    /// Benchmark `RaptorQ` presets (LAN/DERP profiles).
    ///
    /// Emits separate results per profile.
    RaptorqPresets {
        /// Payload size (e.g., "1mb", "100kb").
        #[arg(long, default_value = "1mb")]
        size: String,
    },

    /// Benchmark secret reconstruction (Shamir k-of-n).
    ///
    /// Target: p50 < 150ms / p99 < 750ms
    Secrets {
        /// Threshold (k) for reconstruction.
        #[arg(long, default_value = "3")]
        k: u32,

        /// Total shares (n).
        #[arg(long, default_value = "5")]
        n: u32,
    },

    /// Benchmark canonical CBOR serialization.
    ///
    /// Microbenches for hot primitives in fcp-cbor.
    Cbor {
        /// Specific sub-benchmark (schema-hash, serialize, deserialize, all).
        #[arg(long, default_value = "all")]
        target: CborTarget,
    },

    /// Microbenchmarks for hot primitives (`ObjectId`, capability verification, session MAC).
    Primitives {
        /// Specific sub-benchmark (object-id, capability-verify, session-mac, fcps-frame, all).
        #[arg(long, default_value = "all")]
        target: PrimitiveTarget,
    },

    /// Run all benchmarks and produce a complete report.
    All,
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum MeshPath {
    Direct,
    Derp,
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum CborTarget {
    SchemaHash,
    Serialize,
    Deserialize,
    All,
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum PrimitiveTarget {
    ObjectId,
    CapabilityVerify,
    SessionMac,
    FcpsFrame,
    All,
}

/// Run the benchmark command.
#[allow(clippy::too_many_lines)]
pub fn run(args: BenchArgs) -> anyhow::Result<()> {
    let env = environment::collect();

    let results = match args.command {
        BenchCommand::ConnectorActivate { connector: _ } => {
            // TODO: Implement connector activation benchmarks once fcp-sdk is ready.
            tracing::warn!("connector-activate benchmark not yet implemented (fcp-sdk pending)");
            vec![BenchmarkResult::placeholder(
                "connector-activate",
                "fcp-sdk not yet implemented",
            )]
        }
        BenchCommand::InvokeLocal => {
            // TODO: Implement local invoke benchmarks once fcp-mesh is ready.
            tracing::warn!("invoke-local benchmark not yet implemented (fcp-mesh pending)");
            vec![BenchmarkResult::placeholder(
                "invoke-local",
                "fcp-mesh not yet implemented",
            )]
        }
        BenchCommand::InvokeMesh { path } => {
            let path_name = match path {
                MeshPath::Direct => "direct",
                MeshPath::Derp => "derp",
            };
            // TODO: Implement mesh invoke benchmarks once fcp-mesh is ready.
            tracing::warn!(
                "invoke-mesh --path={} benchmark not yet implemented (fcp-mesh pending)",
                path_name
            );
            vec![BenchmarkResult::placeholder(
                format!("invoke-mesh-{path_name}"),
                "fcp-mesh not yet implemented",
            )]
        }
        BenchCommand::Raptorq { size } => {
            let size_label = normalize_size_label(&size);
            let size_bytes = parse_size_bytes(&size_label)?;
            vec![bench_raptorq(
                &size_label,
                size_bytes,
                args.iterations,
                args.warmup,
            )?]
        }
        BenchCommand::RaptorqPresets { size } => {
            let size_label = normalize_size_label(&size);
            let size_bytes = parse_size_bytes(&size_label)?;
            bench_raptorq_presets(&size_label, size_bytes, args.iterations, args.warmup)?
        }
        BenchCommand::Secrets { k, n } => {
            // TODO: Implement secrets benchmarks once fcp-crypto Shamir is ready.
            tracing::warn!(
                "secrets --k={} --n={} benchmark not yet implemented (fcp-crypto pending)",
                k,
                n
            );
            vec![BenchmarkResult::placeholder(
                format!("secrets-{k}-of-{n}"),
                "fcp-crypto Shamir not yet implemented",
            )]
        }
        BenchCommand::Cbor { target } => cbor::run_benchmarks(target, args.iterations, args.warmup),
        BenchCommand::Primitives { target } => run_primitives(target, args.iterations, args.warmup),
        BenchCommand::All => {
            let mut all_results = Vec::new();

            // Run CBOR benchmarks (the only ones currently implemented).
            all_results.extend(cbor::run_benchmarks(
                CborTarget::All,
                args.iterations,
                args.warmup,
            ));

            // Run hot primitive microbenches.
            all_results.extend(run_primitives(
                PrimitiveTarget::All,
                args.iterations,
                args.warmup,
            ));

            // Run default RaptorQ benchmark (1MB payload).
            let raptorq_size = "1mb";
            let raptorq_bytes = parse_size_bytes(raptorq_size)?;
            all_results.push(bench_raptorq(
                raptorq_size,
                raptorq_bytes,
                args.iterations,
                args.warmup,
            )?);

            // Add placeholders for unimplemented benchmarks.
            all_results.push(BenchmarkResult::placeholder(
                "connector-activate",
                "fcp-sdk not yet implemented",
            ));
            all_results.push(BenchmarkResult::placeholder(
                "invoke-local",
                "fcp-mesh not yet implemented",
            ));
            all_results.push(BenchmarkResult::placeholder(
                "invoke-mesh-direct",
                "fcp-mesh not yet implemented",
            ));
            all_results.push(BenchmarkResult::placeholder(
                "invoke-mesh-derp",
                "fcp-mesh not yet implemented",
            ));
            all_results.push(BenchmarkResult::placeholder(
                "secrets-3-of-5",
                "fcp-crypto Shamir not yet implemented",
            ));

            all_results
        }
    };

    for result in &results {
        tracing::info!(
            bench = %result.name,
            params = %result.parameters,
            samples = result.sample_count,
            warmup = result.warmup_count,
            outliers = result.outliers_detected,
            note = ?result.note,
            "benchmark completed"
        );
    }

    let report = BenchmarkReport::new(env, results);

    match args.format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        OutputFormat::Human => {
            print_human_report(&report);
        }
    }

    Ok(())
}

fn print_human_report(report: &BenchmarkReport) {
    println!("FCP2 Benchmark Report");
    println!("=====================");
    println!();
    println!("Environment:");
    println!(
        "  OS:      {} {}",
        report.environment.os, report.environment.os_version
    );
    println!("  Arch:    {}", report.environment.arch);
    println!("  CPUs:    {}", report.environment.cpu_count);
    if let Some(ref commit) = report.environment.git_commit {
        println!("  Commit:  {commit}");
    }
    println!("  Time:    {}", report.environment.timestamp);
    println!();

    for result in &report.results {
        println!("{}:", result.name);
        if let Some(note) = &result.note {
            println!("  Note: {note}");
        }
        if let Some(ref p) = result.percentiles {
            println!("  p50:  {:>10.3} ms", p.p50_ms);
            println!("  p90:  {:>10.3} ms", p.p90_ms);
            println!("  p95:  {:>10.3} ms", p.p95_ms);
            println!("  p99:  {:>10.3} ms", p.p99_ms);
            println!("  min:  {:>10.3} ms", p.min_ms);
            println!("  max:  {:>10.3} ms", p.max_ms);
        }
        println!("  Samples: {}", result.sample_count);
        println!();
    }
}

fn normalize_size_label(size: &str) -> String {
    size.trim().to_ascii_lowercase()
}

fn parse_size_bytes(size: &str) -> anyhow::Result<usize> {
    let size = size.trim().to_ascii_lowercase();
    if size.is_empty() {
        bail!("size must not be empty");
    }

    let (number, multiplier) = match size.as_str() {
        s if s.ends_with("kb") => (s.trim_end_matches("kb"), 1024_u64),
        s if s.ends_with("mb") => (s.trim_end_matches("mb"), 1024_u64 * 1024),
        s if s.ends_with("gb") => (s.trim_end_matches("gb"), 1024_u64 * 1024 * 1024),
        s if s.ends_with('b') => (s.trim_end_matches('b'), 1_u64),
        _ => (size.as_str(), 1_u64),
    };

    let number = number.trim().replace('_', "");
    if number.is_empty() {
        bail!("size value missing in '{size}'");
    }

    let value: u64 = number
        .parse()
        .map_err(|_| anyhow!("invalid size value '{number}'"))?;
    let bytes = value
        .checked_mul(multiplier)
        .ok_or_else(|| anyhow!("size overflow for '{size}'"))?;

    if bytes == 0 {
        bail!("size must be greater than zero");
    }

    usize::try_from(bytes).map_err(|_| anyhow!("size too large for platform"))
}

fn bench_raptorq(
    size_label: &str,
    size_bytes: usize,
    iterations: u32,
    warmup: u32,
) -> anyhow::Result<BenchmarkResult> {
    use fcp_raptorq::RaptorQConfig;

    let config = RaptorQConfig::default();
    bench_raptorq_with_config(
        format!("raptorq-{size_label}"),
        size_label,
        size_bytes,
        iterations,
        warmup,
        &config,
        None,
    )
}

fn bench_raptorq_presets(
    size_label: &str,
    size_bytes: usize,
    iterations: u32,
    warmup: u32,
) -> anyhow::Result<Vec<BenchmarkResult>> {
    use fcp_raptorq::{RaptorQConfig, RaptorQPathProfile, RaptorQPreset};

    let mut results = Vec::new();
    let presets = [
        (RaptorQPathProfile::Lan, "lan"),
        (RaptorQPathProfile::Derp, "derp"),
    ];

    for (profile, label) in presets {
        let preset = RaptorQPreset::for_profile(profile);
        let config = RaptorQConfig::from_preset(preset)
            .ok_or_else(|| anyhow!("invalid RaptorQ preset for profile {label}"))?;
        results.push(bench_raptorq_with_config(
            format!("raptorq-{label}-{size_label}"),
            size_label,
            size_bytes,
            iterations,
            warmup,
            &config,
            Some(preset),
        )?);
    }

    Ok(results)
}

fn bench_raptorq_with_config(
    name: String,
    size_label: &str,
    size_bytes: usize,
    iterations: u32,
    warmup: u32,
    config: &fcp_raptorq::RaptorQConfig,
    preset: Option<fcp_raptorq::RaptorQPreset>,
) -> anyhow::Result<BenchmarkResult> {
    use fcp_raptorq::{RaptorQDecoder, RaptorQEncoder};

    if size_bytes > config.max_object_size as usize {
        bail!(
            "size {} exceeds RaptorQ max_object_size {}",
            size_bytes,
            config.max_object_size
        );
    }

    let payload = vec![0xAB_u8; size_bytes];
    let encoder = RaptorQEncoder::new(&payload, config)
        .map_err(|err| anyhow!("raptorq encode init failed: {err}"))?;

    let symbol_size = encoder.symbol_size();
    let source_symbols = encoder.source_symbols();
    let repair_symbols = encoder.repair_symbols();
    let total_symbols = encoder.total_symbols();

    let (percentiles, outliers) = runner::run_benchmark_with_result(warmup, iterations, || {
        let encoder = RaptorQEncoder::new(&payload, config).expect("encoder init");
        let symbols = encoder.encode_all();
        let mut decoder = RaptorQDecoder::new(encoder.transmission_info(), config);

        let mut decoded_payload = None;
        for (esi, data) in symbols {
            if let Some(payload) = decoder
                .add_symbol(esi, data)
                .expect("raptorq decode should succeed")
            {
                decoded_payload = Some(payload);
                break;
            }
        }

        decoded_payload
            .expect("raptorq decode did not complete")
            .len()
    });

    let mut parameters = serde_json::json!({
        "size": size_label,
        "size_bytes": size_bytes,
        "symbol_size": symbol_size,
        "source_symbols": source_symbols,
        "repair_symbols": repair_symbols,
        "total_symbols": total_symbols,
        "decode_timeout_ms": config.decode_timeout.as_millis(),
        "max_object_size": config.max_object_size,
    });

    if let Some(preset) = preset {
        let profile = match preset.profile {
            fcp_raptorq::RaptorQPathProfile::Lan => "lan",
            fcp_raptorq::RaptorQPathProfile::Derp => "derp",
        };
        if let Some(map) = parameters.as_object_mut() {
            map.insert(
                "profile".to_string(),
                serde_json::Value::String(profile.to_string()),
            );
            map.insert(
                "max_datagram_bytes".to_string(),
                serde_json::Value::from(preset.max_datagram_bytes),
            );
            map.insert(
                "symbols_per_frame".to_string(),
                serde_json::Value::from(preset.symbols_per_frame),
            );
            map.insert(
                "preferred_symbol_size".to_string(),
                serde_json::Value::from(preset.preferred_symbol_size),
            );
            map.insert(
                "repair_ratio_bps".to_string(),
                serde_json::Value::from(preset.repair_ratio_bps),
            );
        }
    }

    let mut result = BenchmarkResult::new(
        name,
        "RaptorQ encode + decode wall time",
        iterations,
        warmup,
        percentiles,
    )
    .with_parameters(parameters);

    if size_bytes == 1024 * 1024 {
        result = result.with_targets(types::Targets {
            p50_target_ms: 50.0,
            p99_target_ms: 250.0,
        });
    }

    result.outliers_detected = outliers;
    Ok(result)
}

fn run_primitives(target: PrimitiveTarget, iterations: u32, warmup: u32) -> Vec<BenchmarkResult> {
    let mut results = Vec::new();

    if target == PrimitiveTarget::ObjectId || target == PrimitiveTarget::All {
        results.push(bench_object_id(iterations, warmup));
    }

    if target == PrimitiveTarget::CapabilityVerify || target == PrimitiveTarget::All {
        results.push(bench_capability_verify(iterations, warmup));
    }

    if target == PrimitiveTarget::SessionMac || target == PrimitiveTarget::All {
        results.push(bench_session_mac(iterations, warmup));
    }

    if target == PrimitiveTarget::FcpsFrame || target == PrimitiveTarget::All {
        results.push(bench_fcps_frame_parse_mac(iterations, warmup));
    }

    results
}

fn bench_object_id(iterations: u32, warmup: u32) -> BenchmarkResult {
    use fcp_cbor::SchemaId;
    use fcp_core::{ObjectId, ObjectIdKey, ZoneId};
    use semver::Version;

    let zone = ZoneId::work();
    let schema = SchemaId::new("fcp.bench", "ObjectIdPayload", Version::new(1, 0, 0));
    let key = ObjectIdKey::from_bytes([0x11_u8; 32]);
    let payload = vec![0xAB_u8; 1024];

    let (percentiles, outliers) = runner::run_benchmark_with_result(warmup, iterations, || {
        ObjectId::new(&payload, &zone, &schema, &key)
    });

    let mut result = BenchmarkResult::new(
        "object-id-derive",
        "Derive ObjectId from payload, zone, schema, and ObjectIdKey",
        iterations,
        warmup,
        percentiles,
    )
    .with_parameters(serde_json::json!({
        "payload_bytes": payload.len(),
        "zone": zone.as_str(),
        "schema": format!("{}:{}@{}", schema.namespace, schema.name, schema.version),
    }))
    .with_targets(types::Targets {
        p50_target_ms: 0.02,
        p99_target_ms: 0.2,
    });

    result.outliers_detected = outliers;
    result
}

fn bench_capability_verify(iterations: u32, warmup: u32) -> BenchmarkResult {
    use fcp_core::{
        CapabilityToken as CapabilityArtifact, CapabilityVerifier, InstanceId, OperationId, ZoneId,
    };
    use fcp_crypto::{CapabilityTokenBuilder as CapabilityBuilder, Ed25519SigningKey};

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let pub_bytes = verifying_key.to_bytes();

    let now = chrono::Utc::now();
    let expires = now + chrono::Duration::hours(1);
    let zone = ZoneId::work();
    let ops = ["op.test"];

    let cose_capability = CapabilityBuilder::new()
        .capability_id("cap.test")
        .zone_id(zone.as_str())
        .principal("principal:test")
        .operations(&ops)
        .issuer("node:test")
        .validity(now, expires)
        .sign(&signing_key)
        .expect("capability token should sign");

    let capability = CapabilityArtifact {
        raw: cose_capability,
    };

    let verifier = CapabilityVerifier::new(pub_bytes, zone.clone(), InstanceId::new());
    let op = OperationId::new("op.test").expect("operation id must be canonical");
    let cap = fcp_core::CapabilityId::new("cap.test").expect("capability id must be canonical");

    let (percentiles, outliers) = runner::run_benchmark_with_result(warmup, iterations, || {
        verifier
            .verify(&capability, &cap, &op, &[])
            .expect("capability verification should succeed");
    });

    let mut result = BenchmarkResult::new(
        "capability-verify",
        "Verify capability token signature, expiry, zone binding, and grants",
        iterations,
        warmup,
        percentiles,
    )
    .with_parameters(serde_json::json!({
        "ops": ops.len(),
        "zone": zone.as_str(),
        "instance_bound": false,
    }))
    .with_targets(types::Targets {
        p50_target_ms: 0.2,
        p99_target_ms: 1.5,
    });

    result.outliers_detected = outliers;
    result
}

fn bench_session_mac(iterations: u32, warmup: u32) -> BenchmarkResult {
    use fcp_crypto::{Blake3Mac, MacKey};

    let key = MacKey::from_bytes([0x3C_u8; 32]);
    let mac = Blake3Mac::new(&key);
    let message = vec![0x5A_u8; 2048];
    let tag = mac.compute(&message);

    let (percentiles, outliers) = runner::run_benchmark_with_result(warmup, iterations, || {
        mac.verify(&message, &tag)
            .expect("session MAC should verify");
    });

    let mut result = BenchmarkResult::new(
        "session-mac-verify",
        "Verify BLAKE3 session MAC over frame payload",
        iterations,
        warmup,
        percentiles,
    )
    .with_parameters(serde_json::json!({
        "message_bytes": message.len(),
        "mac": "blake3",
        "tag_bytes": fcp_crypto::mac::MAC_SIZE,
    }))
    .with_targets(types::Targets {
        p50_target_ms: 0.05,
        p99_target_ms: 0.5,
    });

    result.outliers_detected = outliers;
    result
}

const FCPS_HEADER_LEN: usize = 114;

#[derive(Clone, Copy)]
struct FcpsHeader {
    frame_seq: u64,
}

fn parse_fcps_header(bytes: &[u8]) -> Option<FcpsHeader> {
    if bytes.len() < FCPS_HEADER_LEN {
        return None;
    }

    let magic = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    if magic != u32::from_le_bytes(*b"FCPS") {
        return None;
    }

    let frame_seq = u64::from_le_bytes(bytes[106..114].try_into().ok()?);

    Some(FcpsHeader { frame_seq })
}

fn bench_fcps_frame_parse_mac(iterations: u32, warmup: u32) -> BenchmarkResult {
    use fcp_crypto::{Blake3Mac, MacKey};

    let symbol_size: u16 = 1024;
    let payload_len: usize = 16 * symbol_size as usize;
    let frame_len = FCPS_HEADER_LEN + payload_len;
    let mut frame = vec![0u8; frame_len];

    frame[0..4].copy_from_slice(b"FCPS");
    frame[4..6].copy_from_slice(&1_u16.to_le_bytes());
    frame[6..8].copy_from_slice(&0_u16.to_le_bytes());

    let payload_len_u32 = u32::try_from(payload_len).expect("payload length fits u32");
    let symbol_size_u32 = u32::from(symbol_size);
    frame[8..12].copy_from_slice(&(payload_len_u32 / symbol_size_u32).to_le_bytes());
    frame[12..16].copy_from_slice(&payload_len_u32.to_le_bytes());
    frame[16..48].copy_from_slice(&[0x11_u8; 32]);
    frame[48..50].copy_from_slice(&symbol_size.to_le_bytes());
    frame[50..58].copy_from_slice(&42_u64.to_le_bytes());
    frame[58..90].copy_from_slice(&[0x22_u8; 32]);
    frame[90..98].copy_from_slice(&7_u64.to_le_bytes());
    frame[98..106].copy_from_slice(&99_u64.to_le_bytes());
    frame[106..114].copy_from_slice(&12345_u64.to_le_bytes());

    let key = MacKey::from_bytes([0x9A_u8; 32]);
    let mac = Blake3Mac::new(&key);
    let tag = mac.compute(&frame);

    let (percentiles, outliers) = runner::run_benchmark_with_result(warmup, iterations, || {
        let header = parse_fcps_header(&frame).expect("valid header");
        mac.verify(&frame, &tag).expect("frame MAC should verify");
        header.frame_seq
    });

    let mut result = BenchmarkResult::new(
        "fcps-frame-parse-mac",
        "Parse FCPS header and verify session MAC",
        iterations,
        warmup,
        percentiles,
    )
    .with_parameters(serde_json::json!({
        "frame_bytes": frame_len,
        "payload_bytes": payload_len,
        "symbol_size": symbol_size,
        "mac": "blake3",
    }))
    .with_targets(types::Targets {
        p50_target_ms: 0.2,
        p99_target_ms: 1.0,
    });

    result.outliers_detected = outliers;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- normalize_size_label ----

    #[test]
    fn normalize_size_label_lowercase() {
        assert_eq!(normalize_size_label("1MB"), "1mb");
    }

    #[test]
    fn normalize_size_label_already_lower() {
        assert_eq!(normalize_size_label("100kb"), "100kb");
    }

    #[test]
    fn normalize_size_label_trims_whitespace() {
        assert_eq!(normalize_size_label("  2gb  "), "2gb");
    }

    #[test]
    fn normalize_size_label_mixed_case() {
        assert_eq!(normalize_size_label("512Kb"), "512kb");
    }

    // ---- parse_size_bytes ----

    #[test]
    fn parse_size_bytes_megabytes() {
        assert_eq!(parse_size_bytes("1mb").unwrap(), 1024 * 1024);
    }

    #[test]
    fn parse_size_bytes_kilobytes() {
        assert_eq!(parse_size_bytes("100kb").unwrap(), 100 * 1024);
    }

    #[test]
    fn parse_size_bytes_gigabytes() {
        assert_eq!(parse_size_bytes("2gb").unwrap(), 2 * 1024 * 1024 * 1024);
    }

    #[test]
    fn parse_size_bytes_raw_bytes_suffix() {
        assert_eq!(parse_size_bytes("512b").unwrap(), 512);
    }

    #[test]
    fn parse_size_bytes_raw_number() {
        assert_eq!(parse_size_bytes("1024").unwrap(), 1024);
    }

    #[test]
    fn parse_size_bytes_with_underscores() {
        assert_eq!(parse_size_bytes("1_000kb").unwrap(), 1000 * 1024);
    }

    #[test]
    fn parse_size_bytes_uppercase() {
        assert_eq!(parse_size_bytes("1MB").unwrap(), 1024 * 1024);
    }

    #[test]
    fn parse_size_bytes_whitespace() {
        assert_eq!(parse_size_bytes("  512kb  ").unwrap(), 512 * 1024);
    }

    #[test]
    fn parse_size_bytes_empty() {
        let err = parse_size_bytes("").unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn parse_size_bytes_zero() {
        let err = parse_size_bytes("0kb").unwrap_err();
        assert!(err.to_string().contains("greater than zero"));
    }

    #[test]
    fn parse_size_bytes_zero_raw() {
        let err = parse_size_bytes("0").unwrap_err();
        assert!(err.to_string().contains("greater than zero"));
    }

    #[test]
    fn parse_size_bytes_invalid_number() {
        let err = parse_size_bytes("abcmb").unwrap_err();
        assert!(err.to_string().contains("invalid size value"));
    }

    #[test]
    fn parse_size_bytes_just_suffix() {
        let err = parse_size_bytes("mb").unwrap_err();
        assert!(err.to_string().contains("size value missing"));
    }

    #[test]
    fn parse_size_bytes_overflow() {
        let err = parse_size_bytes("999999999999999gb").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("overflow") || msg.contains("too large") || msg.contains("invalid"));
    }

    // ---- parse_fcps_header ----

    #[test]
    fn parse_fcps_header_valid() {
        let mut frame = vec![0u8; FCPS_HEADER_LEN];
        frame[0..4].copy_from_slice(b"FCPS");
        frame[106..114].copy_from_slice(&42_u64.to_le_bytes());
        let header = parse_fcps_header(&frame).unwrap();
        assert_eq!(header.frame_seq, 42);
    }

    #[test]
    fn parse_fcps_header_too_short() {
        let frame = vec![0u8; FCPS_HEADER_LEN - 1];
        assert!(parse_fcps_header(&frame).is_none());
    }

    #[test]
    fn parse_fcps_header_wrong_magic() {
        let mut frame = vec![0u8; FCPS_HEADER_LEN];
        frame[0..4].copy_from_slice(b"NOPE");
        assert!(parse_fcps_header(&frame).is_none());
    }

    #[test]
    fn parse_fcps_header_empty() {
        assert!(parse_fcps_header(&[]).is_none());
    }

    #[test]
    fn parse_fcps_header_exact_size() {
        let mut frame = vec![0u8; FCPS_HEADER_LEN];
        frame[0..4].copy_from_slice(b"FCPS");
        frame[106..114].copy_from_slice(&99_u64.to_le_bytes());
        let header = parse_fcps_header(&frame).unwrap();
        assert_eq!(header.frame_seq, 99);
    }

    #[test]
    fn parse_fcps_header_large_seq() {
        let mut frame = vec![0u8; FCPS_HEADER_LEN + 100];
        frame[0..4].copy_from_slice(b"FCPS");
        frame[106..114].copy_from_slice(&u64::MAX.to_le_bytes());
        let header = parse_fcps_header(&frame).unwrap();
        assert_eq!(header.frame_seq, u64::MAX);
    }

    // ---- FCPS_HEADER_LEN ----

    #[test]
    fn fcps_header_len_is_114() {
        assert_eq!(FCPS_HEADER_LEN, 114);
    }

    // ---- BenchmarkResult::placeholder ----

    #[test]
    fn placeholder_result_fields() {
        let result = BenchmarkResult::placeholder("test-bench", "not ready");
        assert_eq!(result.name, "test-bench");
        assert_eq!(result.description, "Not yet implemented");
        assert!(result.percentiles.is_none());
        assert_eq!(result.sample_count, 0);
        assert_eq!(result.warmup_count, 0);
        assert_eq!(result.note.as_deref(), Some("not ready"));
        assert!(result.passed.is_none());
        assert!(result.targets.is_none());
    }

    #[test]
    fn placeholder_result_serde_roundtrip() {
        let result = BenchmarkResult::placeholder("bench-x", "pending");
        let json = serde_json::to_string(&result).unwrap();
        let back: BenchmarkResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "bench-x");
        assert_eq!(back.note.as_deref(), Some("pending"));
        assert!(back.percentiles.is_none());
    }

    // ---- FcpsHeader clone/copy ----

    #[test]
    fn fcps_header_clone_copy() {
        let header = FcpsHeader { frame_seq: 7 };
        let cloned = header;
        let copied = cloned;
        assert_eq!(copied.frame_seq, 7);
    }

    // ---- normalize_size_label additional ----

    #[test]
    fn normalize_size_label_empty_string() {
        assert_eq!(normalize_size_label(""), "");
    }

    #[test]
    fn normalize_size_label_only_whitespace() {
        assert_eq!(normalize_size_label("   "), "");
    }

    #[test]
    fn normalize_size_label_numeric_only() {
        assert_eq!(normalize_size_label("1024"), "1024");
    }

    // ---- parse_size_bytes additional boundaries ----

    #[test]
    fn parse_size_bytes_one_byte() {
        assert_eq!(parse_size_bytes("1b").unwrap(), 1);
    }

    #[test]
    fn parse_size_bytes_one_raw() {
        assert_eq!(parse_size_bytes("1").unwrap(), 1);
    }

    #[test]
    fn parse_size_bytes_large_kb() {
        assert_eq!(parse_size_bytes("10_000kb").unwrap(), 10_000 * 1024);
    }

    #[test]
    fn parse_size_bytes_negative_rejected() {
        let err = parse_size_bytes("-1mb").unwrap_err();
        assert!(err.to_string().contains("invalid size value"));
    }

    #[test]
    fn parse_size_bytes_decimal_rejected() {
        let err = parse_size_bytes("1.5mb").unwrap_err();
        assert!(err.to_string().contains("invalid size value"));
    }

    #[test]
    fn parse_size_bytes_only_underscores_in_number() {
        // "___mb" → number portion is "___", stripped to "" → "size value missing"
        let err = parse_size_bytes("___mb").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("size value missing") || msg.contains("invalid size value"));
    }

    // ---- parse_fcps_header additional ----

    #[test]
    fn parse_fcps_header_zero_seq() {
        let mut frame = vec![0u8; FCPS_HEADER_LEN];
        frame[0..4].copy_from_slice(b"FCPS");
        // frame_seq at 106..114 is already 0
        let header = parse_fcps_header(&frame).unwrap();
        assert_eq!(header.frame_seq, 0);
    }

    #[test]
    fn parse_fcps_header_partial_magic() {
        let mut frame = vec![0u8; FCPS_HEADER_LEN];
        frame[0..3].copy_from_slice(b"FCP");
        // 4th byte is 0, not 'S'
        assert!(parse_fcps_header(&frame).is_none());
    }

    #[test]
    fn parse_fcps_header_one_byte_short() {
        let frame = vec![0u8; FCPS_HEADER_LEN - 1];
        assert!(parse_fcps_header(&frame).is_none());
    }

    #[test]
    fn parse_fcps_header_extra_data_after() {
        let mut frame = vec![0xFFu8; FCPS_HEADER_LEN + 1000];
        frame[0..4].copy_from_slice(b"FCPS");
        frame[106..114].copy_from_slice(&1_u64.to_le_bytes());
        let header = parse_fcps_header(&frame).unwrap();
        assert_eq!(header.frame_seq, 1);
    }

    // ---- enum variant equality ----

    #[test]
    fn output_format_equality() {
        assert!(OutputFormat::Json == OutputFormat::Json);
        assert!(OutputFormat::Human == OutputFormat::Human);
        assert!(OutputFormat::Json != OutputFormat::Human);
    }

    #[test]
    fn mesh_path_equality() {
        assert!(MeshPath::Direct == MeshPath::Direct);
        assert!(MeshPath::Derp == MeshPath::Derp);
        assert!(MeshPath::Direct != MeshPath::Derp);
    }

    #[test]
    fn cbor_target_equality() {
        assert!(CborTarget::All == CborTarget::All);
        assert!(CborTarget::SchemaHash == CborTarget::SchemaHash);
        assert!(CborTarget::Serialize != CborTarget::Deserialize);
    }

    #[test]
    fn primitive_target_equality() {
        assert!(PrimitiveTarget::All == PrimitiveTarget::All);
        assert!(PrimitiveTarget::ObjectId == PrimitiveTarget::ObjectId);
        assert!(PrimitiveTarget::SessionMac != PrimitiveTarget::FcpsFrame);
    }

    // ---- placeholder with format! name ----

    #[test]
    fn placeholder_with_dynamic_name() {
        let k = 3;
        let n = 5;
        let result = BenchmarkResult::placeholder(
            format!("secrets-{k}-of-{n}"),
            "not implemented",
        );
        assert_eq!(result.name, "secrets-3-of-5");
    }

    #[test]
    fn placeholder_with_mesh_path_name() {
        for path_name in &["direct", "derp"] {
            let result = BenchmarkResult::placeholder(
                format!("invoke-mesh-{path_name}"),
                "fcp-mesh not yet implemented",
            );
            assert!(result.name.starts_with("invoke-mesh-"));
            assert_eq!(result.sample_count, 0);
        }
    }

    // ---- FCPS_HEADER_LEN constant ----

    #[test]
    fn fcps_header_len_matches_field_layout() {
        // Layout: magic(4) + version(2) + flags(2) + symbol_count(4) + payload_len(4)
        // + zone_hash(32) + symbol_size(2) + epoch(8) + object_hash(32) +
        // base_esi(8) + ack_epoch(8) + frame_seq(8) = 114
        let computed = 4 + 2 + 2 + 4 + 4 + 32 + 2 + 8 + 32 + 8 + 8 + 8;
        assert_eq!(FCPS_HEADER_LEN, computed);
    }
}
