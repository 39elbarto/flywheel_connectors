//! Deterministic reservoir sampling for audit-chain compaction.
//!
//! The compactor keeps an unbiased bounded sample of owned [`AuditEntry`] values
//! while preserving the original entries byte-for-byte. Callers can use the
//! returned, sequence-sorted sample as a replayable retained-history slice and
//! persist the report as redaction-safe compaction evidence.

#![allow(clippy::module_name_repetitions)]

use serde::{Deserialize, Serialize};

use crate::AuditEntry;

const SCHEMA_VERSION: &str = "fcp.audit.reservoir_compaction.v1";
const ALGORITHM: &str = "reservoir_sampling_algorithm_r";
const SAMPLE_DIGEST_DOMAIN: &[u8] = b"FCP-AUDIT-RESERVOIR-SAMPLE-V1";

/// Result of a reservoir-compaction run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReservoirCompaction {
    /// Replay-sorted retained audit entries.
    pub entries: Vec<AuditEntry>,
    /// Redaction-safe metadata describing the compaction run.
    pub report: ReservoirCompactionReport,
}

/// Redaction-safe evidence describing a reservoir-compaction run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReservoirCompactionReport {
    /// Stable report schema identifier.
    pub schema_version: String,
    /// Sampling algorithm used by this report.
    pub algorithm: String,
    /// Configured maximum number of retained entries.
    pub capacity: u64,
    /// Deterministic sampler seed.
    pub seed: u64,
    /// Number of entries observed by the compactor.
    pub total_observed: u64,
    /// Number of entries retained in the sample.
    pub retained_count: u64,
    /// Number of observed entries not retained.
    pub dropped_count: u64,
    /// Minimum sequence number observed in the input stream.
    pub observed_seq_min: Option<u64>,
    /// Maximum sequence number observed in the input stream.
    pub observed_seq_max: Option<u64>,
    /// Minimum sequence number retained in the output sample.
    pub retained_seq_min: Option<u64>,
    /// Maximum sequence number retained in the output sample.
    pub retained_seq_max: Option<u64>,
    /// BLAKE3 digest over retained `(seq, id)` pairs in replay order.
    pub sample_digest: String,
}

/// Errors raised by reservoir compaction setup.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReservoirCompactionError {
    /// Reservoir capacity must be positive.
    #[error("reservoir capacity must be greater than zero")]
    ZeroCapacity,
}

/// Bounded reservoir sampler for audit entries.
#[derive(Debug, Clone)]
pub struct ReservoirCompactor {
    capacity: usize,
    seed: u64,
    rng: SplitMix64,
    total_observed: u64,
    observed_seq_min: Option<u64>,
    observed_seq_max: Option<u64>,
    entries: Vec<AuditEntry>,
}

impl ReservoirCompactor {
    /// Build a compactor with the supplied capacity and deterministic seed.
    ///
    /// # Errors
    ///
    /// Returns [`ReservoirCompactionError::ZeroCapacity`] when `capacity` is 0.
    pub fn new(capacity: usize, seed: u64) -> Result<Self, ReservoirCompactionError> {
        if capacity == 0 {
            return Err(ReservoirCompactionError::ZeroCapacity);
        }

        Ok(Self {
            capacity,
            seed,
            rng: SplitMix64::new(seed),
            total_observed: 0,
            observed_seq_min: None,
            observed_seq_max: None,
            entries: Vec::with_capacity(capacity),
        })
    }

    /// Add one audit entry to the reservoir.
    pub fn push(&mut self, entry: AuditEntry) {
        self.observe_seq(entry.seq);
        self.total_observed = self.total_observed.saturating_add(1);

        if self.entries.len() < self.capacity {
            self.entries.push(entry);
            return;
        }

        let replacement_index = self.rng.uniform_below(self.total_observed);
        if replacement_index < saturating_u64(self.capacity) {
            if let Ok(index) = usize::try_from(replacement_index) {
                self.entries[index] = entry;
            }
        }
    }

    /// Add every audit entry from an iterator to the reservoir.
    pub fn extend<I>(&mut self, entries: I)
    where
        I: IntoIterator<Item = AuditEntry>,
    {
        for entry in entries {
            self.push(entry);
        }
    }

    /// Finish compaction and return the replay-sorted retained sample.
    #[must_use]
    pub fn finish(mut self) -> ReservoirCompaction {
        self.entries.sort_by(|left, right| {
            left.seq
                .cmp(&right.seq)
                .then_with(|| left.id.cmp(&right.id))
        });

        let retained_count = saturating_u64(self.entries.len());
        let report = ReservoirCompactionReport {
            schema_version: SCHEMA_VERSION.to_string(),
            algorithm: ALGORITHM.to_string(),
            capacity: saturating_u64(self.capacity),
            seed: self.seed,
            total_observed: self.total_observed,
            retained_count,
            dropped_count: self.total_observed.saturating_sub(retained_count),
            observed_seq_min: self.observed_seq_min,
            observed_seq_max: self.observed_seq_max,
            retained_seq_min: self.entries.first().map(|entry| entry.seq),
            retained_seq_max: self.entries.last().map(|entry| entry.seq),
            sample_digest: sample_digest(&self.entries),
        };

        ReservoirCompaction {
            entries: self.entries,
            report,
        }
    }

    fn observe_seq(&mut self, seq: u64) {
        self.observed_seq_min = Some(
            self.observed_seq_min
                .map_or(seq, |current| current.min(seq)),
        );
        self.observed_seq_max = Some(
            self.observed_seq_max
                .map_or(seq, |current| current.max(seq)),
        );
    }
}

/// Compact owned audit entries with deterministic reservoir sampling.
///
/// # Errors
///
/// Returns [`ReservoirCompactionError::ZeroCapacity`] when `capacity` is 0.
pub fn compact_entries<I>(
    entries: I,
    capacity: usize,
    seed: u64,
) -> Result<ReservoirCompaction, ReservoirCompactionError>
where
    I: IntoIterator<Item = AuditEntry>,
{
    let mut compactor = ReservoirCompactor::new(capacity, seed)?;
    compactor.extend(entries);
    Ok(compactor.finish())
}

#[derive(Debug, Clone)]
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    const fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut mixed = self.state;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        mixed ^ (mixed >> 31)
    }

    fn uniform_below(&mut self, upper_exclusive: u64) -> u64 {
        debug_assert!(upper_exclusive > 0);
        let threshold = upper_exclusive.wrapping_neg() % upper_exclusive;
        loop {
            let candidate = self.next_u64();
            if candidate >= threshold {
                return candidate % upper_exclusive;
            }
        }
    }
}

fn saturating_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn sample_digest(entries: &[AuditEntry]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SAMPLE_DIGEST_DOMAIN);

    for entry in entries {
        let id_bytes = entry.id.as_bytes();
        hasher.update(&entry.seq.to_le_bytes());
        hasher.update(&saturating_u64(id_bytes.len()).to_le_bytes());
        hasher.update(id_bytes);
    }

    format!("blake3:{}", hasher.finalize().to_hex())
}
