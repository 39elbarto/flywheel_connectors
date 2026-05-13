# StatPack Methodology

`fcp-bench::stats::StatPack` is the common performance evidence summary for
FCP benchmark gates. It records p50, p99, p99.9, mean, sample standard
deviation, a percentile-bootstrap confidence interval for the mean, tail
amplification, and Welch unequal-variance comparison data.

The implementation is deterministic. `StatPack::from_samples` filters non-finite
values, sorts with `f64::total_cmp`, uses linear interpolation for percentile
estimates, and runs 1000 deterministic bootstrap resamples for the default 95%
confidence interval. `StatPack::with_resamples` exposes the resample count for
test fixtures and fast local probes.

Welch comparisons use the original sample count and variance retained inside the
pack, then compute the Satterthwaite degrees of freedom and a two-sided
Student-t p-value. Zero-variance or insufficient sample comparisons return
`NaN` instead of panicking so gate callers can classify invalid evidence
explicitly.

`tail_amp` is `(p999 - p99) / (p99 - p50)`. It is a compact signal for
tail-growth amplification, not a replacement for full histograms or benchmark
artifacts.

Redaction posture: StatPack logs and JSON values contain only aggregate numeric
statistics and sample counts. Raw samples, command lines, hostnames, user names,
connector IDs, and secret-bearing artifact paths are not emitted by this helper.
Structured tracing uses target `fcp.bench.stats`; field names use the
`fcp_bench_stats_*` prefix because Rust tracing macros require identifier-safe
field names, and OTLP exporters can map that prefix back to the documented
`fcp.bench.stats.*` attribute namespace.
