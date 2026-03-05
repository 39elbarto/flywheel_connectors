//! RaptorQ inactivation decoder with deterministic pivoting.
//!
//! Implements a two-phase decoding strategy:
//! 1. **Peeling**: Iteratively solve degree-1 equations (belief propagation)
//! 2. **Inactivation**: Mark stubborn symbols as inactive, defer to Gaussian elimination
//!
//! # Determinism
//!
//! All operations are deterministic:
//! - Pivot selection uses stable lexicographic ordering
//! - Tie-breaking rules are explicit (lowest column index wins)
//! - Same received symbols in same order produce identical decode results

use super::gf256::{Gf256, gf256_addmul_slice, gf256_mul_slice};
use super::systematic::{ConstraintMatrix, SystematicParams};

use std::collections::{BTreeSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::Arc;

// ============================================================================
// Deterministic hasher (inlined from asupersync DetHasher)
// ============================================================================

/// Deterministic, non-cryptographic hasher with fixed seed.
///
/// Provides reproducible hashes across runs for cache-key fingerprinting.
#[derive(Debug, Clone)]
struct DetHasher {
    state: u64,
}

impl DetHasher {
    /// Fixed seed ensures deterministic hashes across runs.
    const SEED: u64 = 0x16f1_1fe8_9b0d_677c;
    /// Prime multiplier for mixing.
    const MULTIPLIER: u64 = 0x517c_c1b7_2722_0a95;

    #[inline]
    fn mix_byte(&mut self, byte: u8) {
        self.state = self.state.wrapping_mul(Self::MULTIPLIER);
        self.state ^= u64::from(byte);
    }
}

impl Default for DetHasher {
    fn default() -> Self {
        Self { state: Self::SEED }
    }
}

impl Hasher for DetHasher {
    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.mix_byte(byte);
        }
    }

    fn write_u8(&mut self, i: u8) {
        self.mix_byte(i);
    }

    fn write_u16(&mut self, i: u16) {
        let bytes = i.to_le_bytes();
        self.mix_byte(bytes[0]);
        self.mix_byte(bytes[1]);
    }

    fn write_u32(&mut self, i: u32) {
        let bytes = i.to_le_bytes();
        self.mix_byte(bytes[0]);
        self.mix_byte(bytes[1]);
        self.mix_byte(bytes[2]);
        self.mix_byte(bytes[3]);
    }

    fn write_u64(&mut self, i: u64) {
        let bytes = i.to_le_bytes();
        self.mix_byte(bytes[0]);
        self.mix_byte(bytes[1]);
        self.mix_byte(bytes[2]);
        self.mix_byte(bytes[3]);
        self.mix_byte(bytes[4]);
        self.mix_byte(bytes[5]);
        self.mix_byte(bytes[6]);
        self.mix_byte(bytes[7]);
    }

    fn write_u128(&mut self, i: u128) {
        let bytes = i.to_le_bytes();
        for &byte in &bytes {
            self.mix_byte(byte);
        }
    }

    fn write_usize(&mut self, i: usize) {
        // Always cast to u64 for width-independent consistent hashing.
        self.write_u64(i as u64);
    }

    fn write_i8(&mut self, i: i8) {
        self.write_u8(i as u8);
    }

    fn write_i16(&mut self, i: i16) {
        self.write_u16(i as u16);
    }

    fn write_i32(&mut self, i: i32) {
        self.write_u32(i as u32);
    }

    fn write_i64(&mut self, i: i64) {
        self.write_u64(i as u64);
    }

    fn write_i128(&mut self, i: i128) {
        self.write_u128(i as u128);
    }

    fn write_isize(&mut self, i: isize) {
        self.write_i64(i as i64);
    }

    fn finish(&self) -> u64 {
        // Final mixing for better distribution.
        let mut h = self.state;
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
        h ^= h >> 33;
        h = h.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
        h ^= h >> 33;
        h
    }
}

// ============================================================================
// Decoder types
// ============================================================================

/// A received symbol (source or repair) with its equation.
#[derive(Debug, Clone)]
pub struct ReceivedSymbol {
    /// Encoding Symbol Index (ESI).
    pub esi: u32,
    /// Whether this is a source symbol (ESI < K).
    pub is_source: bool,
    /// Column indices that this symbol depends on (intermediate symbol indices).
    /// For source symbols, this is just `[esi]`. For repair, computed from LT encoding.
    pub columns: Vec<usize>,
    /// GF(256) coefficients for each column (same length as `columns`).
    /// For XOR-based LT, all coefficients are 1.
    pub coefficients: Vec<Gf256>,
    /// The symbol data.
    pub data: Vec<u8>,
}

/// Reason for decode failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// Not enough symbols received to solve the system.
    #[error("insufficient symbols: received {received}, required {required}")]
    InsufficientSymbols {
        /// Number of symbols received.
        received: usize,
        /// Minimum required (L = K + S + H).
        required: usize,
    },
    /// Matrix became singular during Gaussian elimination.
    #[error("singular matrix at row {row}")]
    SingularMatrix {
        /// Deterministic witness row for elimination failure.
        ///
        /// This may be either:
        /// - the original unsolved column id where no pivot was found, or
        /// - an equation row index that reduced to `0 = b` (inconsistent system).
        row: usize,
    },
    /// Symbol size mismatch.
    #[error("symbol size mismatch: expected {expected}, actual {actual}")]
    SymbolSizeMismatch {
        /// Expected size.
        expected: usize,
        /// Actual size found.
        actual: usize,
    },
    /// Received symbol has mismatched equation vectors.
    #[error(
        "symbol equation arity mismatch for ESI {esi}: {columns} columns vs {coefficients} coefficients"
    )]
    SymbolEquationArityMismatch {
        /// ESI of the malformed symbol.
        esi: u32,
        /// Number of column indices provided.
        columns: usize,
        /// Number of coefficients provided.
        coefficients: usize,
    },
    /// Received symbol references a column outside the decode domain [0, L).
    #[error("column index out of range for ESI {esi}: column {column} >= {max_valid}")]
    ColumnIndexOutOfRange {
        /// ESI of the malformed symbol.
        esi: u32,
        /// Offending column index.
        column: usize,
        /// Exclusive upper bound for valid columns.
        max_valid: usize,
    },
    /// Internal corruption guard: reconstructed output does not satisfy an
    /// input equation and is therefore unsafe to return as success.
    #[error(
        "corrupt decoded output for ESI {esi} at byte {byte_index}: expected {expected:#04x}, actual {actual:#04x}"
    )]
    CorruptDecodedOutput {
        /// ESI of the mismatched equation row.
        esi: u32,
        /// First byte index where mismatch was detected.
        byte_index: usize,
        /// Reconstructed byte from decoded intermediate symbols.
        expected: u8,
        /// Received RHS byte from the input symbol.
        actual: u8,
    },
}

/// Decode failure classification used to separate retryable failures from
/// malformed/corruption failures at the API boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeFailureClass {
    /// Retry may succeed with additional symbols/redundancy.
    Recoverable,
    /// Input is malformed or decode invariants were violated.
    Unrecoverable,
}

impl DecodeError {
    /// Classify this decode failure as recoverable or unrecoverable.
    #[must_use]
    pub const fn failure_class(&self) -> DecodeFailureClass {
        match self {
            Self::InsufficientSymbols { .. } | Self::SingularMatrix { .. } => {
                DecodeFailureClass::Recoverable
            }
            Self::SymbolSizeMismatch { .. }
            | Self::SymbolEquationArityMismatch { .. }
            | Self::ColumnIndexOutOfRange { .. }
            | Self::CorruptDecodedOutput { .. } => DecodeFailureClass::Unrecoverable,
        }
    }

    /// True when this failure can be retried by supplying additional symbols.
    #[must_use]
    pub const fn is_recoverable(&self) -> bool {
        matches!(self.failure_class(), DecodeFailureClass::Recoverable)
    }

    /// True when this failure indicates malformed input or corruption.
    #[must_use]
    pub const fn is_unrecoverable(&self) -> bool {
        matches!(self.failure_class(), DecodeFailureClass::Unrecoverable)
    }
}

/// Decode statistics for observability.
#[derive(Debug, Clone, Default)]
pub struct DecodeStats {
    /// Symbols solved via peeling (degree-1 propagation).
    pub peeled: usize,
    /// Symbols marked as inactive.
    pub inactivated: usize,
    /// Gaussian elimination row operations performed.
    pub gauss_ops: usize,
    /// Total pivot selections made.
    pub pivots_selected: usize,
    /// True when the decoder entered hard-regime inactivation mode.
    ///
    /// Hard regime is a deterministic fallback for dense/near-square decode
    /// systems where naive pivoting is more likely to encounter fragile paths.
    pub hard_regime_activated: bool,
    /// Number of pivots selected by the hard-regime Markowitz-style strategy.
    pub markowitz_pivots: usize,
    /// Number of times baseline elimination deterministically retried in hard regime.
    pub hard_regime_fallbacks: usize,
    /// Hard-regime branch selected for dense elimination.
    pub hard_regime_branch: Option<&'static str>,
    /// Deterministic reason an accelerated hard-regime branch fell back to conservative mode.
    pub hard_regime_conservative_fallback_reason: Option<&'static str>,
    /// Number of equation indices pushed into the deterministic peel queue.
    pub peel_queue_pushes: usize,
    /// Number of equation indices popped from the deterministic peel queue.
    pub peel_queue_pops: usize,
    /// Maximum queue depth observed during peeling.
    pub peel_frontier_peak: usize,
    /// Number of rows in the extracted dense core presented to elimination.
    pub dense_core_rows: usize,
    /// Number of columns in the extracted dense core presented to elimination.
    pub dense_core_cols: usize,
    /// Number of zero-information rows dropped while extracting the dense core.
    pub dense_core_dropped_rows: usize,
    /// Deterministic reason we fell back from peeling into dense elimination.
    pub peeling_fallback_reason: Option<&'static str>,
    /// Runtime policy mode selected for dense elimination planning.
    pub policy_mode: Option<&'static str>,
    /// Deterministic reason string for the runtime policy decision.
    pub policy_reason: Option<&'static str>,
    /// Replay pointer for policy-decision forensics.
    pub policy_replay_ref: Option<&'static str>,
    /// Policy feature: matrix density in permille.
    pub policy_density_permille: usize,
    /// Policy feature: estimated rank deficit pressure in permille.
    pub policy_rank_deficit_permille: usize,
    /// Policy feature: inactivation pressure in permille.
    pub policy_inactivation_pressure_permille: usize,
    /// Policy feature: row/column overhead ratio in permille.
    pub policy_overhead_ratio_permille: usize,
    /// True if policy feature extraction exhausted its strict budget.
    pub policy_budget_exhausted: bool,
    /// Expected-loss term for conservative baseline mode.
    pub policy_baseline_loss: u32,
    /// Expected-loss term for high-support mode.
    pub policy_high_support_loss: u32,
    /// Expected-loss term for block-schur mode.
    pub policy_block_schur_loss: u32,
    /// Number of dense-factor cache hits during this decode.
    pub factor_cache_hits: usize,
    /// Number of dense-factor cache misses during this decode.
    pub factor_cache_misses: usize,
    /// Number of dense-factor cache insertions during this decode.
    pub factor_cache_inserts: usize,
    /// Number of dense-factor cache evictions during this decode.
    pub factor_cache_evictions: usize,
    /// Number of fingerprint collisions observed while probing cache keys.
    pub factor_cache_lookup_collisions: usize,
    /// Last dense-factor cache key fingerprint consulted by the decoder.
    pub factor_cache_last_key: Option<u64>,
    /// Deterministic reason for the most recent dense-factor cache decision.
    pub factor_cache_last_reason: Option<&'static str>,
    /// Whether the most recent cache probe was eligible for artifact reuse.
    pub factor_cache_last_reuse_eligible: Option<bool>,
    /// Number of entries resident in the dense-factor cache after the last operation.
    pub factor_cache_entries: usize,
    /// Bounded capacity used by the dense-factor cache policy.
    pub factor_cache_capacity: usize,
    /// True when the wavefront decode pipeline was used.
    pub wavefront_active: bool,
    /// Number of bounded assembly+peel batches processed by the wavefront pipeline.
    pub wavefront_batches: usize,
    /// Number of symbols peeled during assembly batches (overlap region).
    pub wavefront_overlap_peeled: usize,
    /// Wavefront batch size used for assembly+peel fusion.
    pub wavefront_batch_size: usize,
}

/// Result of successful decoding.
#[derive(Debug)]
pub struct DecodeResult {
    /// Recovered intermediate symbols (L symbols).
    pub intermediate: Vec<Vec<u8>>,
    /// Recovered source symbols (first K of intermediate).
    pub source: Vec<Vec<u8>>,
    /// Decode statistics.
    pub stats: DecodeStats,
}

// ============================================================================
// Decoder state
// ============================================================================

/// Internal decoder state during the decode process.
struct DecoderState {
    /// Encoding parameters.
    params: SystematicParams,
    /// Received equations (row-major, each row is an equation).
    equations: Vec<Equation>,
    /// Right-hand side data for each equation.
    rhs: Vec<Vec<u8>>,
    /// Solved intermediate symbols (None if not yet solved).
    solved: Vec<Option<Vec<u8>>>,
    /// Set of active (unsolved, not inactivated) columns.
    active_cols: BTreeSet<usize>,
    /// Set of inactivated columns (will be solved via Gaussian elimination).
    inactive_cols: BTreeSet<usize>,
    /// Statistics.
    stats: DecodeStats,
}

const DENSE_FACTOR_CACHE_CAPACITY: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DenseFactorCacheResult {
    Hit,
    MissInserted,
    MissEvicted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DenseFactorCacheLookup {
    Hit(Arc<DenseFactorArtifact>),
    MissNoEntry,
    MissFingerprintCollision,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DenseFactorArtifact {
    dense_cols: Vec<usize>,
    col_to_dense: DenseColIndexMap,
}

impl DenseFactorArtifact {
    fn new(dense_cols: Vec<usize>) -> Self {
        let col_to_dense = build_dense_col_index_map(&dense_cols);
        Self {
            dense_cols,
            col_to_dense,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DenseColIndexMap {
    Direct(Vec<usize>),
    SortedPairs(Vec<(usize, usize)>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DenseFactorSignature {
    fingerprint: u64,
    unsolved: Vec<usize>,
    row_offsets: Vec<usize>,
    row_terms_flat: Vec<(usize, u8)>,
}

impl DenseFactorSignature {
    fn from_equations(equations: &[Equation], dense_rows: &[usize], unsolved: &[usize]) -> Self {
        let mut row_offsets = Vec::with_capacity(dense_rows.len());
        // Upper bound avoids growth reallocations in bursty decode signatures.
        let row_terms_capacity = dense_rows
            .iter()
            .map(|&eq_idx| equations[eq_idx].terms.len())
            .sum();
        let mut row_terms_flat = Vec::with_capacity(row_terms_capacity);
        for &eq_idx in dense_rows {
            let mut unsolved_cursor = 0usize;
            for &(col, coef) in &equations[eq_idx].terms {
                if coef.is_zero() {
                    continue;
                }
                while unsolved_cursor < unsolved.len() && unsolved[unsolved_cursor] < col {
                    unsolved_cursor += 1;
                }
                if unsolved_cursor >= unsolved.len() {
                    break;
                }
                if unsolved[unsolved_cursor] == col {
                    row_terms_flat.push((col, coef.raw()));
                }
            }
            row_offsets.push(row_terms_flat.len());
        }

        let mut hasher = DetHasher::default();
        unsolved.hash(&mut hasher);
        row_offsets.hash(&mut hasher);
        row_terms_flat.hash(&mut hasher);
        let fingerprint = hasher.finish();

        Self {
            fingerprint,
            unsolved: unsolved.to_vec(),
            row_offsets,
            row_terms_flat,
        }
    }
}

#[derive(Debug, Clone)]
struct DenseFactorCacheEntry {
    signature: DenseFactorSignature,
    artifact: Arc<DenseFactorArtifact>,
}

#[derive(Debug, Default)]
struct DenseFactorCache {
    entries: VecDeque<DenseFactorCacheEntry>,
}

impl DenseFactorCache {
    fn lookup(&self, signature: &DenseFactorSignature) -> DenseFactorCacheLookup {
        let mut saw_fingerprint_collision = false;
        for entry in &self.entries {
            if entry.signature.fingerprint != signature.fingerprint {
                continue;
            }
            if entry.signature == *signature {
                return DenseFactorCacheLookup::Hit(entry.artifact.clone());
            }
            saw_fingerprint_collision = true;
        }

        if saw_fingerprint_collision {
            DenseFactorCacheLookup::MissFingerprintCollision
        } else {
            DenseFactorCacheLookup::MissNoEntry
        }
    }

    fn insert(
        &mut self,
        signature: DenseFactorSignature,
        artifact: Arc<DenseFactorArtifact>,
    ) -> DenseFactorCacheResult {
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|entry| entry.signature == signature)
        {
            existing.artifact = artifact;
            return DenseFactorCacheResult::MissInserted;
        }

        let result = if self.entries.len() >= DENSE_FACTOR_CACHE_CAPACITY {
            let _ = self.entries.pop_front();
            DenseFactorCacheResult::MissEvicted
        } else {
            DenseFactorCacheResult::MissInserted
        };
        self.entries.push_back(DenseFactorCacheEntry {
            signature,
            artifact,
        });
        result
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// A sparse equation over GF(256).
#[derive(Debug, Clone)]
struct Equation {
    /// (column_index, coefficient) pairs, sorted by column index.
    terms: Vec<(usize, Gf256)>,
    /// Whether this equation has been used (solved or eliminated).
    used: bool,
}

impl Equation {
    fn new(columns: Vec<usize>, coefficients: Vec<Gf256>) -> Self {
        let mut terms: Vec<_> = columns.into_iter().zip(coefficients).collect();
        // Sort by column index for deterministic ordering
        terms.sort_by_key(|(col, _)| *col);
        // Merge duplicates (XOR coefficients)
        let mut merged = Vec::with_capacity(terms.len());
        for (col, coef) in terms {
            if let Some((last_col, last_coef)) = merged.last_mut() {
                if *last_col == col {
                    *last_coef += coef;
                    continue;
                }
            }
            merged.push((col, coef));
        }
        // Remove zero coefficients
        merged.retain(|(_, coef)| !coef.is_zero());
        Self {
            terms: merged,
            used: false,
        }
    }

    /// Returns the degree (number of nonzero terms).
    fn degree(&self) -> usize {
        self.terms.len()
    }

    /// Returns the lowest column index (pivot candidate).
    #[allow(dead_code)]
    fn lowest_col(&self) -> Option<usize> {
        self.terms.first().map(|(col, _)| *col)
    }

    /// Returns the coefficient for the given column, or zero.
    fn coef(&self, col: usize) -> Gf256 {
        self.terms
            .binary_search_by_key(&col, |(c, _)| *c)
            .map_or(Gf256::ZERO, |idx| self.terms[idx].1)
    }
}

#[inline]
fn original_col_for_dense(unsolved: &[usize], dense_col: usize) -> usize {
    unsolved.get(dense_col).copied().unwrap_or(dense_col)
}

#[inline]
fn singular_matrix_error(unsolved: &[usize], dense_col: usize) -> DecodeError {
    DecodeError::SingularMatrix {
        row: original_col_for_dense(unsolved, dense_col),
    }
}

#[inline]
fn inconsistent_matrix_error(unused_eqs: &[usize], dense_row: usize) -> DecodeError {
    DecodeError::SingularMatrix {
        row: unused_eqs.get(dense_row).copied().unwrap_or(dense_row),
    }
}

fn first_inconsistent_dense_row(
    a: &[Gf256],
    n_rows: usize,
    n_cols: usize,
    b: &[Vec<u8>],
) -> Option<usize> {
    (0..n_rows).find(|&row| {
        let row_off = row * n_cols;
        a[row_off..row_off + n_cols]
            .iter()
            .all(|coef| coef.is_zero())
            && b[row].iter().any(|&byte| byte != 0)
    })
}

#[inline]
fn active_degree_one_col(state: &DecoderState, eq: &Equation) -> Option<usize> {
    if eq.used || eq.degree() != 1 {
        return None;
    }
    let col = eq.terms[0].0;
    if state.active_cols.contains(&col) && state.solved[col].is_none() {
        Some(col)
    } else {
        None
    }
}

fn build_dense_core_rows(
    state: &DecoderState,
    unused_eqs: &[usize],
    unsolved: &[usize],
) -> Result<(Vec<usize>, usize), DecodeError> {
    let mut unsolved_mask = vec![false; state.params.l];
    for &col in unsolved {
        unsolved_mask[col] = true;
    }

    let mut dense_rows = Vec::with_capacity(unused_eqs.len());
    let mut dropped_zero_rows = 0usize;

    for &eq_idx in unused_eqs {
        let has_unsolved_term = state.equations[eq_idx]
            .terms
            .iter()
            .any(|(col, coef)| unsolved_mask[*col] && !coef.is_zero());
        if has_unsolved_term {
            dense_rows.push(eq_idx);
            continue;
        }

        if state.rhs[eq_idx].iter().any(|&byte| byte != 0) {
            return Err(DecodeError::SingularMatrix { row: eq_idx });
        }
        dropped_zero_rows += 1;
    }

    Ok((dense_rows, dropped_zero_rows))
}

const DENSE_COL_ABSENT: usize = usize::MAX;
const DENSE_COL_DIRECT_MAP_RANGE_RATIO: usize = 8;

#[inline]
fn build_dense_col_index_map(unsolved: &[usize]) -> DenseColIndexMap {
    let Some(max_col) = unsolved.iter().copied().max() else {
        return DenseColIndexMap::Direct(Vec::new());
    };

    let direct_map_max_col = unsolved
        .len()
        .saturating_mul(DENSE_COL_DIRECT_MAP_RANGE_RATIO);
    if max_col <= direct_map_max_col {
        let mut col_to_dense = vec![DENSE_COL_ABSENT; max_col.saturating_add(1)];
        for (dense_col, &col) in unsolved.iter().enumerate() {
            col_to_dense[col] = dense_col;
        }
        DenseColIndexMap::Direct(col_to_dense)
    } else {
        let mut pairs: Vec<(usize, usize)> = unsolved
            .iter()
            .copied()
            .enumerate()
            .map(|(dense_col, col)| (col, dense_col))
            .collect();
        pairs.sort_by_key(|(col, _)| *col);
        DenseColIndexMap::SortedPairs(pairs)
    }
}

#[inline]
fn dense_col_index_from_direct(map: &[usize], col: usize) -> Option<usize> {
    let dense_col = *map.get(col)?;
    if dense_col == DENSE_COL_ABSENT {
        return None;
    }
    Some(dense_col)
}

#[inline]
fn dense_col_index_from_sorted_pairs(pairs: &[(usize, usize)], col: usize) -> Option<usize> {
    let idx = pairs
        .binary_search_by_key(&col, |(candidate_col, _)| *candidate_col)
        .ok()?;
    Some(pairs[idx].1)
}

#[inline]
fn dense_col_index(col_to_dense: &DenseColIndexMap, col: usize) -> Option<usize> {
    match col_to_dense {
        DenseColIndexMap::Direct(map) => dense_col_index_from_direct(map, col),
        DenseColIndexMap::SortedPairs(pairs) => dense_col_index_from_sorted_pairs(pairs, col),
    }
}

fn sparse_first_dense_columns(
    equations: &[Equation],
    dense_rows: &[usize],
    unsolved: &[usize],
) -> Vec<usize> {
    if unsolved.len() < 2 {
        return unsolved.to_vec();
    }

    let mut support = vec![0usize; unsolved.len()];

    // Hot-path optimization: runtime unsolved columns are deterministically
    // sorted; use a two-pointer scan to avoid allocating an index map.
    if unsolved.windows(2).all(|w| w[0] <= w[1]) {
        for &eq_idx in dense_rows {
            let mut unsolved_cursor = 0usize;
            for &(col, coef) in &equations[eq_idx].terms {
                if coef.is_zero() {
                    continue;
                }
                while unsolved_cursor < unsolved.len() && unsolved[unsolved_cursor] < col {
                    unsolved_cursor += 1;
                }
                if unsolved_cursor >= unsolved.len() {
                    break;
                }
                if unsolved[unsolved_cursor] == col {
                    support[unsolved_cursor] += 1;
                }
            }
        }
    } else {
        // Compatibility fallback for non-canonical caller input.
        let col_to_dense = build_dense_col_index_map(unsolved);
        for &eq_idx in dense_rows {
            for &(col, coef) in &equations[eq_idx].terms {
                if coef.is_zero() {
                    continue;
                }
                if let Some(dense_col) = dense_col_index(&col_to_dense, col) {
                    support[dense_col] += 1;
                }
            }
        }
    }

    let mut ordered: Vec<(usize, usize)> = unsolved
        .iter()
        .copied()
        .enumerate()
        .map(|(dense_col, col)| (col, support[dense_col]))
        .collect();

    // Sparse-first ordering shrinks expected fill-in while remaining deterministic.
    ordered.sort_by(|(col_a, support_a), (col_b, support_b)| {
        support_a.cmp(support_b).then_with(|| col_a.cmp(col_b))
    });
    ordered.into_iter().map(|(col, _)| col).collect()
}

const HARD_REGIME_MIN_COLS: usize = 8;
const HARD_REGIME_DENSITY_PERCENT: usize = 35;
const HARD_REGIME_NEAR_SQUARE_EXTRA_ROWS: usize = 2;
const BLOCK_SCHUR_MIN_COLS: usize = 12;
const BLOCK_SCHUR_MIN_DENSITY_PERCENT: usize = 45;
const BLOCK_SCHUR_TRAILING_COLS: usize = 4;
const HYBRID_SPARSE_COST_NUMERATOR: usize = 3;
const HYBRID_SPARSE_COST_DENOMINATOR: usize = 5;
const SMALL_ROW_DENSE_FASTPATH_COLS: usize = 4;
const POLICY_FEATURE_BUDGET_CELLS: usize = 4096;
const POLICY_REPLAY_REF: &str = "replay:rq-track-f-runtime-policy-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DecoderPolicyFeatures {
    density_permille: usize,
    rank_deficit_permille: usize,
    inactivation_pressure_permille: usize,
    overhead_ratio_permille: usize,
    budget_exhausted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecoderPolicyMode {
    ConservativeBaseline,
    HighSupportFirst,
    BlockSchurLowRank,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DecoderPolicyDecision {
    mode: DecoderPolicyMode,
    features: DecoderPolicyFeatures,
    baseline_loss: u32,
    high_support_loss: u32,
    block_schur_loss: u32,
    reason: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HardRegimePlan {
    Markowitz,
    BlockSchurLowRank { split_col: usize },
}

impl HardRegimePlan {
    const fn label(self) -> &'static str {
        match self {
            Self::Markowitz => "markowitz",
            Self::BlockSchurLowRank { .. } => "block_schur_low_rank",
        }
    }
}

fn matrix_nonzero_count(a: &[Gf256]) -> usize {
    a.iter().filter(|coef| !coef.is_zero()).count()
}

fn clamp_usize_to_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn compute_decoder_policy_features(
    n_rows: usize,
    n_cols: usize,
    dense_nonzeros: usize,
    unsupported_cols: usize,
    inactivation_pressure_permille: usize,
) -> DecoderPolicyFeatures {
    if n_rows == 0 || n_cols == 0 {
        return DecoderPolicyFeatures {
            density_permille: 0,
            rank_deficit_permille: 0,
            inactivation_pressure_permille,
            overhead_ratio_permille: 0,
            budget_exhausted: false,
        };
    }

    let total_cells = n_rows.saturating_mul(n_cols);
    let density_permille = dense_nonzeros.saturating_mul(1000) / total_cells.max(1);
    let rank_deficit_permille = unsupported_cols.saturating_mul(1000) / n_cols;
    let overhead_ratio_permille = n_rows.saturating_sub(n_cols).saturating_mul(1000) / n_cols;

    DecoderPolicyFeatures {
        density_permille,
        rank_deficit_permille,
        inactivation_pressure_permille,
        overhead_ratio_permille,
        budget_exhausted: total_cells > POLICY_FEATURE_BUDGET_CELLS,
    }
}

fn policy_losses(features: DecoderPolicyFeatures, n_cols: usize) -> (u32, u32, u32) {
    let density = clamp_usize_to_u32(features.density_permille);
    let rank_deficit = clamp_usize_to_u32(features.rank_deficit_permille);
    let inactivation_pressure = clamp_usize_to_u32(features.inactivation_pressure_permille);
    let overhead = clamp_usize_to_u32(features.overhead_ratio_permille);

    let baseline_loss = 400u32
        .saturating_add(density.saturating_mul(3))
        .saturating_add(rank_deficit.saturating_mul(4))
        .saturating_add(inactivation_pressure.saturating_mul(2))
        .saturating_add(overhead);

    let high_support_loss = 700u32
        .saturating_add(density)
        .saturating_add(rank_deficit.saturating_mul(3))
        .saturating_add(inactivation_pressure)
        .saturating_add(overhead / 2);

    let block_schur_loss = if n_cols < BLOCK_SCHUR_MIN_COLS {
        u32::MAX
    } else {
        750u32
            .saturating_add(density / 2)
            .saturating_add(rank_deficit.saturating_mul(2))
            .saturating_add(inactivation_pressure)
            .saturating_add(overhead / 3)
    };

    (baseline_loss, high_support_loss, block_schur_loss)
}

fn choose_runtime_decoder_policy(
    n_rows: usize,
    n_cols: usize,
    dense_nonzeros: usize,
    unsupported_cols: usize,
    inactivation_pressure_permille: usize,
) -> DecoderPolicyDecision {
    let features = compute_decoder_policy_features(
        n_rows,
        n_cols,
        dense_nonzeros,
        unsupported_cols,
        inactivation_pressure_permille,
    );

    let (baseline_loss, high_support_loss, mut block_schur_loss) = policy_losses(features, n_cols);
    if features.budget_exhausted {
        return DecoderPolicyDecision {
            mode: DecoderPolicyMode::ConservativeBaseline,
            features,
            baseline_loss,
            high_support_loss,
            block_schur_loss,
            reason: "policy_budget_exhausted_conservative",
        };
    }

    let hard_gate = n_cols >= HARD_REGIME_MIN_COLS
        && (features.density_permille >= HARD_REGIME_DENSITY_PERCENT.saturating_mul(10)
            || n_rows <= n_cols.saturating_add(HARD_REGIME_NEAR_SQUARE_EXTRA_ROWS));
    if !hard_gate {
        return DecoderPolicyDecision {
            mode: DecoderPolicyMode::ConservativeBaseline,
            features,
            baseline_loss,
            high_support_loss,
            block_schur_loss,
            reason: "expected_loss_conservative_gate",
        };
    }

    let block_gate = n_cols >= BLOCK_SCHUR_MIN_COLS
        && features.density_permille >= BLOCK_SCHUR_MIN_DENSITY_PERCENT.saturating_mul(10)
        && n_cols > BLOCK_SCHUR_TRAILING_COLS;
    if !block_gate {
        block_schur_loss = u32::MAX;
    }
    let mode = if block_schur_loss < high_support_loss {
        DecoderPolicyMode::BlockSchurLowRank
    } else {
        DecoderPolicyMode::HighSupportFirst
    };

    DecoderPolicyDecision {
        mode,
        features,
        baseline_loss,
        high_support_loss,
        block_schur_loss,
        reason: "expected_loss_minimum",
    }
}

const fn decoder_policy_mode_label(mode: DecoderPolicyMode) -> &'static str {
    match mode {
        DecoderPolicyMode::ConservativeBaseline => "conservative_baseline",
        DecoderPolicyMode::HighSupportFirst => "high_support_first",
        DecoderPolicyMode::BlockSchurLowRank => "block_schur_low_rank",
    }
}

fn apply_policy_decision_to_stats(stats: &mut DecodeStats, decision: DecoderPolicyDecision) {
    stats.policy_mode = Some(decoder_policy_mode_label(decision.mode));
    stats.policy_reason = Some(decision.reason);
    stats.policy_replay_ref = Some(POLICY_REPLAY_REF);
    stats.policy_density_permille = decision.features.density_permille;
    stats.policy_rank_deficit_permille = decision.features.rank_deficit_permille;
    stats.policy_inactivation_pressure_permille = decision.features.inactivation_pressure_permille;
    stats.policy_overhead_ratio_permille = decision.features.overhead_ratio_permille;
    stats.policy_budget_exhausted = decision.features.budget_exhausted;
    stats.policy_baseline_loss = decision.baseline_loss;
    stats.policy_high_support_loss = decision.high_support_loss;
    stats.policy_block_schur_loss = decision.block_schur_loss;
}

#[derive(Debug, Clone, Copy)]
struct DenseFactorCacheObservation {
    key: u64,
    result: DenseFactorCacheResult,
    reason: &'static str,
    reuse_eligible: bool,
    fingerprint_collision: bool,
    cache_entries: usize,
    cache_capacity: usize,
}

fn apply_dense_factor_cache_observation(
    stats: &mut DecodeStats,
    observation: DenseFactorCacheObservation,
) {
    stats.factor_cache_last_key = Some(observation.key);
    stats.factor_cache_last_reason = Some(observation.reason);
    stats.factor_cache_last_reuse_eligible = Some(observation.reuse_eligible);
    stats.factor_cache_entries = observation.cache_entries;
    stats.factor_cache_capacity = observation.cache_capacity;
    if observation.fingerprint_collision {
        stats.factor_cache_lookup_collisions += 1;
    }

    match observation.result {
        DenseFactorCacheResult::Hit => {
            stats.factor_cache_hits += 1;
        }
        DenseFactorCacheResult::MissInserted => {
            stats.factor_cache_misses += 1;
            stats.factor_cache_inserts += 1;
        }
        DenseFactorCacheResult::MissEvicted => {
            stats.factor_cache_misses += 1;
            stats.factor_cache_inserts += 1;
            stats.factor_cache_evictions += 1;
        }
    }
}

fn row_nonzero_count(a: &[Gf256], n_cols: usize, row: usize) -> usize {
    let row_off = row * n_cols;
    a[row_off..row_off + n_cols]
        .iter()
        .filter(|coef| !coef.is_zero())
        .count()
}

#[inline]
fn should_use_sparse_row_update(pivot_nnz: usize, n_cols: usize) -> bool {
    if n_cols == 0 {
        return false;
    }

    // Explicit cost model: compare sparse-vs-dense column-touch counts with
    // a conservative overhead multiplier for sparse index iteration.
    pivot_nnz.saturating_mul(HYBRID_SPARSE_COST_DENOMINATOR)
        <= n_cols.saturating_mul(HYBRID_SPARSE_COST_NUMERATOR)
}

#[allow(dead_code)]
fn pivot_nonzero_columns(pivot_row: &[Gf256], n_cols: usize) -> Vec<usize> {
    let mut cols = Vec::with_capacity(n_cols.min(32));
    for (idx, coef) in pivot_row.iter().take(n_cols).enumerate() {
        if !coef.is_zero() {
            cols.push(idx);
        }
    }
    cols
}

fn sparse_update_columns_if_beneficial(pivot_row: &[Gf256], n_cols: usize) -> Option<Vec<usize>> {
    if n_cols == 0 {
        return None;
    }

    // Equivalent threshold to should_use_sparse_row_update(pivot_nnz, n_cols).
    let threshold =
        n_cols.saturating_mul(HYBRID_SPARSE_COST_NUMERATOR) / HYBRID_SPARSE_COST_DENOMINATOR;

    if n_cols <= SMALL_ROW_DENSE_FASTPATH_COLS {
        // Very small rows are sensitive to per-pivot heap allocation overhead.
        // Use an allocation-free density pass; collect columns only if sparse.
        let mut sparse_nnz = 0usize;
        for coef in pivot_row.iter().take(n_cols) {
            if coef.is_zero() {
                continue;
            }
            sparse_nnz += 1;
            if sparse_nnz > threshold {
                return None;
            }
        }

        let mut cols = Vec::with_capacity(sparse_nnz.max(1));
        for (idx, coef) in pivot_row.iter().take(n_cols).enumerate() {
            if !coef.is_zero() {
                cols.push(idx);
            }
        }
        return Some(cols);
    }

    // For larger rows, one-pass collection avoids an extra scan on sparse pivots.
    let mut seen = 0usize;
    let mut cols = Vec::with_capacity((threshold + 1).min(n_cols).max(1));
    for (idx, coef) in pivot_row.iter().take(n_cols).enumerate() {
        if coef.is_zero() {
            continue;
        }
        seen += 1;
        if seen > threshold {
            return None;
        }
        cols.push(idx);
    }
    Some(cols)
}

fn should_activate_hard_regime(n_rows: usize, n_cols: usize, a: &[Gf256]) -> bool {
    if n_cols < HARD_REGIME_MIN_COLS {
        return false;
    }

    let total_cells = n_rows.saturating_mul(n_cols);
    if total_cells == 0 {
        return false;
    }

    let nonzeros = matrix_nonzero_count(a);
    let dense =
        nonzeros.saturating_mul(100) >= total_cells.saturating_mul(HARD_REGIME_DENSITY_PERCENT);
    let near_square = n_rows <= n_cols.saturating_add(HARD_REGIME_NEAR_SQUARE_EXTRA_ROWS);

    dense || near_square
}

fn select_hard_regime_plan(n_rows: usize, n_cols: usize, a: &[Gf256]) -> HardRegimePlan {
    let total_cells = n_rows.saturating_mul(n_cols);
    if n_cols < BLOCK_SCHUR_MIN_COLS || total_cells == 0 {
        return HardRegimePlan::Markowitz;
    }
    let nonzeros = matrix_nonzero_count(a);
    let dense_enough =
        nonzeros.saturating_mul(100) >= total_cells.saturating_mul(BLOCK_SCHUR_MIN_DENSITY_PERCENT);
    if !dense_enough || n_cols <= BLOCK_SCHUR_TRAILING_COLS {
        return HardRegimePlan::Markowitz;
    }
    let split_col = n_cols - BLOCK_SCHUR_TRAILING_COLS;
    HardRegimePlan::BlockSchurLowRank { split_col }
}

fn row_cross_block_nnz(
    a: &[Gf256],
    n_cols: usize,
    row: usize,
    split_col: usize,
    col: usize,
) -> usize {
    let row_off = row * n_cols;
    let row_slice = &a[row_off..row_off + n_cols];
    if col < split_col {
        row_slice[split_col..]
            .iter()
            .filter(|coef| !coef.is_zero())
            .count()
    } else {
        row_slice[..split_col]
            .iter()
            .filter(|coef| !coef.is_zero())
            .count()
    }
}

fn select_pivot_row(
    a: &[Gf256],
    n_rows: usize,
    n_cols: usize,
    col: usize,
    row_used: &[bool],
    hard_regime: bool,
    hard_plan: HardRegimePlan,
) -> Option<usize> {
    if !hard_regime {
        return (0..n_rows).find(|&row| !row_used[row] && !a[row * n_cols + col].is_zero());
    }

    let mut best: Option<(usize, usize, usize)> = None;
    for row in 0..n_rows {
        if row_used[row] || a[row * n_cols + col].is_zero() {
            continue;
        }
        let cross_block_nnz = match hard_plan {
            HardRegimePlan::Markowitz => 0,
            HardRegimePlan::BlockSchurLowRank { split_col } => {
                row_cross_block_nnz(a, n_cols, row, split_col, col)
            }
        };
        let nnz = row_nonzero_count(a, n_cols, row);
        match best {
            None => best = Some((row, cross_block_nnz, nnz)),
            Some((_best_row, best_cross, _best_nnz)) if cross_block_nnz < best_cross => {
                best = Some((row, cross_block_nnz, nnz));
            }
            Some((_best_row, best_cross, best_nnz))
                if cross_block_nnz == best_cross && nnz < best_nnz =>
            {
                best = Some((row, cross_block_nnz, nnz));
            }
            Some((best_row, best_cross, best_nnz))
                if cross_block_nnz == best_cross && nnz == best_nnz && row < best_row =>
            {
                best = Some((row, cross_block_nnz, nnz));
            }
            _ => {}
        }
    }

    best.map(|(row, _, _)| row)
}

// ============================================================================
// Inactivation decoder
// ============================================================================

/// Inactivation decoder for RaptorQ.
///
/// Decodes received symbols (source or repair) to recover intermediate
/// symbols, then extracts the original source data.
pub struct InactivationDecoder {
    params: SystematicParams,
    seed: u64,
    dense_factor_cache: parking_lot::Mutex<DenseFactorCache>,
}

impl InactivationDecoder {
    /// Create a new decoder for the given parameters.
    #[must_use]
    pub fn new(k: usize, symbol_size: usize, seed: u64) -> Self {
        let params = SystematicParams::for_source_block(k, symbol_size);
        Self {
            params,
            seed,
            dense_factor_cache: parking_lot::Mutex::new(DenseFactorCache::default()),
        }
    }

    /// Returns the encoding parameters.
    #[must_use]
    pub const fn params(&self) -> &SystematicParams {
        &self.params
    }

    fn validate_input(&self, symbols: &[ReceivedSymbol]) -> Result<(), DecodeError> {
        let l = self.params.l;
        let symbol_size = self.params.symbol_size;

        if symbols.len() < l {
            return Err(DecodeError::InsufficientSymbols {
                received: symbols.len(),
                required: l,
            });
        }

        for sym in symbols {
            if sym.data.len() != symbol_size {
                return Err(DecodeError::SymbolSizeMismatch {
                    expected: symbol_size,
                    actual: sym.data.len(),
                });
            }

            if sym.columns.len() != sym.coefficients.len() {
                return Err(DecodeError::SymbolEquationArityMismatch {
                    esi: sym.esi,
                    columns: sym.columns.len(),
                    coefficients: sym.coefficients.len(),
                });
            }

            for &column in &sym.columns {
                if column >= l {
                    return Err(DecodeError::ColumnIndexOutOfRange {
                        esi: sym.esi,
                        column,
                        max_valid: l,
                    });
                }
            }
        }

        Ok(())
    }

    fn verify_decoded_output(
        &self,
        symbols: &[ReceivedSymbol],
        intermediate: &[Vec<u8>],
    ) -> Result<(), DecodeError> {
        let symbol_size = self.params.symbol_size;
        // Reuse a single scratch buffer across rows to avoid per-symbol
        // heap allocation in decode hot paths.
        let mut reconstructed = vec![0u8; symbol_size];

        for sym in symbols {
            if sym.is_source
                && sym.columns.len() == 1
                && sym.coefficients.len() == 1
                && sym.coefficients[0] == Gf256::ONE
            {
                let source_col = sym.columns[0];
                let expected = &intermediate[source_col];
                if let Some(byte_index) = first_mismatch_byte(expected, &sym.data) {
                    return Err(DecodeError::CorruptDecodedOutput {
                        esi: sym.esi,
                        byte_index,
                        expected: expected[byte_index],
                        actual: sym.data[byte_index],
                    });
                }
                continue;
            }

            reconstructed.fill(0);
            for (&column, &coefficient) in sym.columns.iter().zip(sym.coefficients.iter()) {
                if coefficient.is_zero() {
                    continue;
                }
                gf256_addmul_slice(&mut reconstructed, &intermediate[column], coefficient);
            }
            if let Some(byte_index) = first_mismatch_byte(&reconstructed, &sym.data) {
                return Err(DecodeError::CorruptDecodedOutput {
                    esi: sym.esi,
                    byte_index,
                    expected: reconstructed[byte_index],
                    actual: sym.data[byte_index],
                });
            }
        }

        Ok(())
    }

    /// Decode from received symbols.
    ///
    /// `symbols` should contain at least `L` symbols (K source + S LDPC + H HDPC overhead).
    /// Returns the decoded source symbols on success.
    pub fn decode(&self, symbols: &[ReceivedSymbol]) -> Result<DecodeResult, DecodeError> {
        let k = self.params.k;
        let symbol_size = self.params.symbol_size;

        self.validate_input(symbols)?;

        // Build decoder state
        let mut state = self.build_state(symbols);

        // Phase 1: Peeling
        Self::peel(&mut state);

        // Phase 2: Inactivation + Gaussian elimination
        self.inactivate_and_solve(&mut state)?;

        // Extract results
        let intermediate: Vec<Vec<u8>> = state
            .solved
            .into_iter()
            .map(|opt| opt.unwrap_or_else(|| vec![0u8; symbol_size]))
            .collect();
        self.verify_decoded_output(symbols, &intermediate)?;

        let source: Vec<Vec<u8>> = intermediate[..k].to_vec();

        Ok(DecodeResult {
            intermediate,
            source,
            stats: state.stats,
        })
    }

    /// Decode using the bounded wavefront pipeline.
    ///
    /// Instead of sequential assembly->peel->solve, this pipeline fuses
    /// assembly and peeling into bounded batches: symbols are assembled in
    /// chunks of `batch_size`, and after each chunk the peeling queue is
    /// drained. This reduces pipeline bubbles by overlapping assembly with
    /// peeling, so degree-1 equations discovered early are solved while
    /// remaining symbols are still being assembled.
    ///
    /// The solve phase (inactivation + Gaussian elimination) runs after
    /// all batches are processed, identical to the sequential path.
    ///
    /// Correctness: produces identical results to `decode()` because
    /// peeling order is deterministic (FIFO queue, same equation ordering)
    /// and the dense solve phase sees the same final state.
    ///
    /// `batch_size` controls the wavefront width. Smaller batches increase
    /// overlap but add per-batch overhead. A batch size of 0 means "use
    /// all symbols at once" (equivalent to sequential mode).
    pub fn decode_wavefront(
        &self,
        symbols: &[ReceivedSymbol],
        batch_size: usize,
    ) -> Result<DecodeResult, DecodeError> {
        let k = self.params.k;
        let symbol_size = self.params.symbol_size;
        let l = self.params.l;

        self.validate_input(symbols)?;

        // A batch_size of 0 falls back to sequential (single batch = all symbols).
        let effective_batch = if batch_size == 0 {
            symbols.len()
        } else {
            batch_size
        };

        // Initialize state with empty equations; we'll add them in batches.
        let active_cols: BTreeSet<usize> = (0..l).collect();
        let mut state = DecoderState {
            params: self.params.clone(),
            equations: Vec::with_capacity(symbols.len()),
            rhs: Vec::with_capacity(symbols.len()),
            solved: vec![None; l],
            active_cols,
            inactive_cols: BTreeSet::new(),
            stats: DecodeStats::default(),
        };
        state.stats.wavefront_active = true;
        state.stats.wavefront_batch_size = effective_batch;

        // Wavefront: assemble symbols in bounded batches and peel after each.
        let mut total_overlap_peeled = 0usize;
        let mut batch_count = 0usize;
        let mut queue = VecDeque::new();
        let mut queued = Vec::new();

        for chunk in symbols.chunks(effective_batch) {
            let base_eq_idx = state.equations.len();
            // Assembly: add this batch of symbols as equations.
            for sym in chunk {
                let eq = Equation::new(sym.columns.clone(), sym.coefficients.clone());
                state.equations.push(eq);
                state.rhs.push(sym.data.clone());
            }
            queued.resize(state.equations.len(), false);

            // Catch-up: apply already-peeled solutions to newly assembled equations.
            // This ensures new equations see the same reduced state they would in
            // the sequential path where all equations are present before peeling.
            for idx in base_eq_idx..state.equations.len() {
                let eq = &state.equations[idx];
                // Collect columns that have been solved and appear in this equation.
                let solved_terms: Vec<(usize, Gf256)> = eq
                    .terms
                    .iter()
                    .filter(|(col, coef)| !coef.is_zero() && state.solved[*col].is_some())
                    .copied()
                    .collect();
                for (col, eq_coef) in &solved_terms {
                    let solution = state.solved[*col].as_ref().unwrap();
                    gf256_addmul_slice(&mut state.rhs[idx], solution, *eq_coef);
                    if let Ok(pos) = state.equations[idx]
                        .terms
                        .binary_search_by_key(col, |(c, _)| *c)
                    {
                        state.equations[idx].terms.remove(pos);
                    }
                }
            }

            // Scan newly added equations for degree-1 candidates.
            for (idx, queued_flag) in queued.iter_mut().enumerate().skip(base_eq_idx) {
                if !*queued_flag && active_degree_one_col(&state, &state.equations[idx]).is_some() {
                    queue.push_back(idx);
                    *queued_flag = true;
                    state.stats.peel_queue_pushes += 1;
                }
            }
            state.stats.peel_frontier_peak = state.stats.peel_frontier_peak.max(queue.len());

            // Peel: drain the queue after this batch.
            let peeled_before = state.stats.peeled;
            Self::peel_from_queue(&mut state, &mut queue, &mut queued);
            let peeled_this_batch = state.stats.peeled - peeled_before;
            if batch_count > 0 {
                // Only count overlap peeling from non-first batches,
                // since the first batch has no prior assembly to overlap with.
                total_overlap_peeled += peeled_this_batch;
            }
            batch_count += 1;
        }

        state.stats.wavefront_batches = batch_count;
        state.stats.wavefront_overlap_peeled = total_overlap_peeled;

        // Phase 2: Inactivation + Gaussian elimination (same as sequential).
        self.inactivate_and_solve(&mut state)?;

        // Extract results.
        let intermediate: Vec<Vec<u8>> = state
            .solved
            .into_iter()
            .map(|opt| opt.unwrap_or_else(|| vec![0u8; symbol_size]))
            .collect();
        self.verify_decoded_output(symbols, &intermediate)?;

        let source: Vec<Vec<u8>> = intermediate[..k].to_vec();

        Ok(DecodeResult {
            intermediate,
            source,
            stats: state.stats,
        })
    }

    /// Peel from an existing queue, extending as new degree-1 equations are discovered.
    ///
    /// This is the core peeling loop factored out so it can be called
    /// incrementally by the wavefront pipeline after each assembly batch.
    fn peel_from_queue(state: &mut DecoderState, queue: &mut VecDeque<usize>, queued: &mut [bool]) {
        while let Some(eq_idx) = queue.pop_front() {
            state.stats.peel_queue_pops += 1;
            queued[eq_idx] = false;

            let Some(col) = active_degree_one_col(state, &state.equations[eq_idx]) else {
                continue;
            };

            // Solve this equation.
            let (_col, coef) = state.equations[eq_idx].terms[0];
            state.equations[eq_idx].used = true;

            let mut solution = std::mem::take(&mut state.rhs[eq_idx]);
            if coef != Gf256::ONE {
                let inv = coef.inv();
                gf256_mul_slice(&mut solution, inv);
            }

            state.active_cols.remove(&col);
            state.stats.peeled += 1;

            // Propagate to other equations.
            let active_cols = &state.active_cols;
            let solved = &state.solved;
            for (i, (eq, rhs)) in state
                .equations
                .iter_mut()
                .zip(state.rhs.iter_mut())
                .enumerate()
            {
                if eq.used {
                    continue;
                }
                let eq_coef = eq.coef(col);
                if eq_coef.is_zero() {
                    continue;
                }
                gf256_addmul_slice(rhs, &solution, eq_coef);
                if let Ok(pos) = eq.terms.binary_search_by_key(&col, |(c, _)| *c) {
                    eq.terms.remove(pos);
                }

                if !queued[i] && eq.degree() == 1 {
                    let next_col = eq.terms[0].0;
                    if active_cols.contains(&next_col) && solved[next_col].is_none() {
                        queue.push_back(i);
                        queued[i] = true;
                        state.stats.peel_queue_pushes += 1;
                    }
                }
            }

            state.stats.peel_frontier_peak = state.stats.peel_frontier_peak.max(queue.len());
            state.solved[col] = Some(solution);
        }
    }

    /// Build initial decoder state from received symbols.
    ///
    /// The caller is responsible for including LDPC/HDPC constraint equations
    /// (with zero RHS) in the received symbols if needed. The higher-level
    /// `decode` module handles this by building constraint rows from
    /// the constraint matrix.
    fn build_state(&self, symbols: &[ReceivedSymbol]) -> DecoderState {
        let l = self.params.l;

        let mut equations = Vec::with_capacity(symbols.len());
        let mut rhs = Vec::with_capacity(symbols.len());

        // Add received symbol equations
        for sym in symbols {
            let eq = Equation::new(sym.columns.clone(), sym.coefficients.clone());
            equations.push(eq);
            rhs.push(sym.data.clone());
        }

        let active_cols: BTreeSet<usize> = (0..l).collect();

        DecoderState {
            params: self.params.clone(),
            equations,
            rhs,
            solved: vec![None; l],
            active_cols,
            inactive_cols: BTreeSet::new(),
            stats: DecodeStats::default(),
        }
    }

    fn dense_factor_with_cache(
        &self,
        equations: &[Equation],
        dense_rows: &[usize],
        unsolved: &[usize],
    ) -> (Arc<DenseFactorArtifact>, DenseFactorCacheObservation) {
        let signature = DenseFactorSignature::from_equations(equations, dense_rows, unsolved);
        let cache_key = signature.fingerprint;
        let (lookup, cache_entries_at_lookup) = {
            let cache = self.dense_factor_cache.lock();
            (cache.lookup(&signature), cache.len())
        };

        if let DenseFactorCacheLookup::Hit(artifact) = lookup {
            return (
                artifact,
                DenseFactorCacheObservation {
                    key: cache_key,
                    result: DenseFactorCacheResult::Hit,
                    reason: "signature_match_reuse",
                    reuse_eligible: true,
                    fingerprint_collision: false,
                    cache_entries: cache_entries_at_lookup,
                    cache_capacity: DENSE_FACTOR_CACHE_CAPACITY,
                },
            );
        }

        let saw_fingerprint_collision =
            matches!(lookup, DenseFactorCacheLookup::MissFingerprintCollision);
        let artifact = Arc::new(DenseFactorArtifact::new(sparse_first_dense_columns(
            equations, dense_rows, unsolved,
        )));
        let (result, cache_entries) = {
            let mut cache = self.dense_factor_cache.lock();
            let result = cache.insert(signature, Arc::clone(&artifact));
            (result, cache.len())
        };
        let reason = if saw_fingerprint_collision {
            "fingerprint_collision_rebuild"
        } else {
            match result {
                DenseFactorCacheResult::Hit => "signature_match_reuse",
                DenseFactorCacheResult::MissInserted => "cache_miss_rebuild",
                DenseFactorCacheResult::MissEvicted => "cache_miss_evicted_oldest",
            }
        };
        (
            artifact,
            DenseFactorCacheObservation {
                key: cache_key,
                result,
                reason,
                reuse_eligible: false,
                fingerprint_collision: saw_fingerprint_collision,
                cache_entries,
                cache_capacity: DENSE_FACTOR_CACHE_CAPACITY,
            },
        )
    }

    /// Generate constraint symbols (LDPC + HDPC) with zero data.
    ///
    /// These should be included in the received symbols when decoding.
    /// The higher-level `decode` module handles this automatically; this method
    /// is provided for direct decoder testing.
    #[must_use]
    pub fn constraint_symbols(&self) -> Vec<ReceivedSymbol> {
        let s = self.params.s;
        let h = self.params.h;
        let symbol_size = self.params.symbol_size;
        let base_rows = s + h;

        // Build the constraint matrix (same as encoder uses)
        let constraints = ConstraintMatrix::build(&self.params, self.seed);

        let mut result = Vec::with_capacity(base_rows);

        // Extract the first S+H rows (LDPC + HDPC constraints)
        for row in 0..base_rows {
            let (columns, coefficients) = Self::constraint_row_equation(&constraints, row);
            result.push(ReceivedSymbol {
                esi: row as u32,
                is_source: false,
                columns,
                coefficients,
                data: vec![0u8; symbol_size],
            });
        }

        result
    }

    /// Extract a sparse equation from a constraint matrix row.
    fn constraint_row_equation(
        constraints: &ConstraintMatrix,
        row: usize,
    ) -> (Vec<usize>, Vec<Gf256>) {
        let mut columns = Vec::new();
        let mut coefficients = Vec::new();
        for col in 0..constraints.cols {
            let coeff = constraints.get(row, col);
            if !coeff.is_zero() {
                columns.push(col);
                coefficients.push(coeff);
            }
        }
        (columns, coefficients)
    }

    /// Phase 1: Peeling (belief propagation).
    ///
    /// Find degree-1 equations and solve them, propagating the solution
    /// to other equations.
    fn peel(state: &mut DecoderState) {
        let mut queue = VecDeque::new();
        let mut queued = vec![false; state.equations.len()];
        for (idx, eq) in state.equations.iter().enumerate() {
            if active_degree_one_col(state, eq).is_some() {
                queue.push_back(idx);
                queued[idx] = true;
                state.stats.peel_queue_pushes += 1;
            }
        }
        state.stats.peel_frontier_peak = state.stats.peel_frontier_peak.max(queue.len());

        while let Some(eq_idx) = queue.pop_front() {
            state.stats.peel_queue_pops += 1;
            queued[eq_idx] = false;

            let Some(col) = active_degree_one_col(state, &state.equations[eq_idx]) else {
                continue;
            };

            // Solve this equation
            let (_col, coef) = state.equations[eq_idx].terms[0];
            state.equations[eq_idx].used = true;

            // Compute the solution: intermediate[col] = rhs[eq_idx] / coef
            let mut solution = std::mem::take(&mut state.rhs[eq_idx]);
            if coef != Gf256::ONE {
                let inv = coef.inv();
                gf256_mul_slice(&mut solution, inv);
            }

            state.active_cols.remove(&col);
            state.stats.peeled += 1;

            // Propagate to other equations: subtract col's contribution
            let active_cols = &state.active_cols;
            let solved = &state.solved;
            for (i, eq) in state.equations.iter_mut().enumerate() {
                if eq.used {
                    continue;
                }
                let eq_coef = eq.coef(col);
                if eq_coef.is_zero() {
                    continue;
                }
                // rhs[i] -= eq_coef * solution
                gf256_addmul_slice(&mut state.rhs[i], &solution, eq_coef);
                // Remove the term from the equation.
                // Binary search is efficient since terms are sorted by column index.
                if let Ok(pos) = eq.terms.binary_search_by_key(&col, |(c, _)| *c) {
                    eq.terms.remove(pos);
                }

                if !queued[i] && !eq.used && eq.degree() == 1 {
                    let next_col = eq.terms[0].0;
                    if active_cols.contains(&next_col) && solved[next_col].is_none() {
                        queue.push_back(i);
                        queued[i] = true;
                        state.stats.peel_queue_pushes += 1;
                    }
                }
            }

            state.stats.peel_frontier_peak = state.stats.peel_frontier_peak.max(queue.len());

            // Move solution instead of cloning (avoids allocation)
            state.solved[col] = Some(solution);
        }
    }

    /// Phase 2: Inactivation + Gaussian elimination.
    #[allow(clippy::too_many_lines)]
    fn inactivate_and_solve(&self, state: &mut DecoderState) -> Result<(), DecodeError> {
        let symbol_size = self.params.symbol_size;

        // Collect remaining unsolved columns
        let unsolved: Vec<usize> = state
            .active_cols
            .iter()
            .filter(|&&col| state.solved[col].is_none())
            .copied()
            .collect();

        if unsolved.is_empty() {
            return Ok(());
        }
        state.stats.peeling_fallback_reason = Some("peeling_exhausted_to_dense_core");

        // Collect unused equations
        let unused_eqs: Vec<usize> = state
            .equations
            .iter()
            .enumerate()
            .filter_map(|(i, eq)| if eq.used { None } else { Some(i) })
            .collect();
        let (dense_rows, dropped_zero_rows) = build_dense_core_rows(state, &unused_eqs, &unsolved)?;
        state.stats.dense_core_dropped_rows += dropped_zero_rows;

        // Mark all remaining unsolved columns as inactive
        for &col in &unsolved {
            state.inactive_cols.insert(col);
            state.active_cols.remove(&col);
            state.stats.inactivated += 1;
        }

        // Reorder dense elimination columns deterministically and reuse cached
        // dense skeleton metadata when signatures match.
        let (dense_factor, cache_observation) =
            self.dense_factor_with_cache(&state.equations, &dense_rows, &unsolved);
        apply_dense_factor_cache_observation(&mut state.stats, cache_observation);
        let dense_cols = &dense_factor.dense_cols;
        let col_to_dense = &dense_factor.col_to_dense;

        // Build dense submatrix for Gaussian elimination
        // Rows = unused equations, Columns = unsolved columns
        let n_rows = dense_rows.len();
        let n_cols = dense_cols.len();
        let inactivation_pressure_permille =
            unsolved.len().saturating_mul(1000) / state.params.l.max(1);
        state.stats.dense_core_rows = n_rows;
        state.stats.dense_core_cols = n_cols;

        if n_rows < n_cols {
            return Err(DecodeError::InsufficientSymbols {
                received: n_rows,
                required: n_cols,
            });
        }

        // Build flat row-major dense matrix A and RHS vector b.
        // Flat layout avoids per-row heap allocation and improves cache locality.
        // Move (take) RHS data from state instead of cloning to avoid O(n_rows * symbol_size)
        // heap allocation in this hot path.
        let dense_size = n_rows
            .checked_mul(n_cols)
            .ok_or(DecodeError::InsufficientSymbols {
                received: n_rows,
                required: n_cols,
            })?;
        let mut a = vec![Gf256::ZERO; dense_size];
        let mut dense_nonzeros = 0usize;
        let mut dense_col_support = vec![0usize; n_cols];
        let mut b: Vec<Vec<u8>> = Vec::with_capacity(n_rows);

        for (row, &eq_idx) in dense_rows.iter().enumerate() {
            let row_off = row * n_cols;
            for &(col, coef) in &state.equations[eq_idx].terms {
                if let Some(dense_col) = dense_col_index(col_to_dense, col) {
                    a[row_off + dense_col] = coef;
                    if !coef.is_zero() {
                        dense_nonzeros += 1;
                        dense_col_support[dense_col] += 1;
                    }
                }
            }
            b.push(std::mem::take(&mut state.rhs[eq_idx]));
        }
        let unsupported_cols = dense_col_support
            .iter()
            .filter(|&&support| support == 0)
            .count();

        let decision = choose_runtime_decoder_policy(
            n_rows,
            n_cols,
            dense_nonzeros,
            unsupported_cols,
            inactivation_pressure_permille,
        );
        apply_policy_decision_to_stats(&mut state.stats, decision);
        let mut hard_regime = !matches!(decision.mode, DecoderPolicyMode::ConservativeBaseline);
        let mut hard_plan = match decision.mode {
            DecoderPolicyMode::ConservativeBaseline | DecoderPolicyMode::HighSupportFirst => {
                HardRegimePlan::Markowitz
            }
            DecoderPolicyMode::BlockSchurLowRank => select_hard_regime_plan(n_rows, n_cols, &a),
        };
        let retry_rhs_snapshot = (!hard_regime
            || matches!(hard_plan, HardRegimePlan::BlockSchurLowRank { .. }))
        .then(|| snapshot_dense_rhs(&b, symbol_size));
        if hard_regime {
            state.stats.hard_regime_activated = true;
            state.stats.hard_regime_branch = Some(hard_plan.label());
        } else if decision.reason == "policy_budget_exhausted_conservative" {
            state.stats.hard_regime_conservative_fallback_reason = Some(decision.reason);
        }

        let mut pivot_row = vec![usize::MAX; n_cols];
        loop {
            pivot_row.fill(usize::MAX);

            // Gaussian elimination with partial pivoting.
            // Pre-allocate a single pivot buffer to avoid per-column clones.
            let mut row_used = vec![false; n_rows];
            let mut pivot_buf = vec![Gf256::ZERO; n_cols];
            let mut pivot_rhs = vec![0u8; symbol_size];
            let mut gauss_ops = 0usize;
            let mut pivots_selected = 0usize;
            let mut markowitz_pivots = 0usize;
            let mut elimination_error = None;

            for col in 0..n_cols {
                let pivot =
                    select_pivot_row(&a, n_rows, n_cols, col, &row_used, hard_regime, hard_plan);
                let Some(prow) = pivot else {
                    elimination_error = Some(singular_matrix_error(dense_cols, col));
                    break;
                };

                pivot_row[col] = prow;
                row_used[prow] = true;
                pivots_selected += 1;
                if hard_regime && matches!(hard_plan, HardRegimePlan::Markowitz) {
                    markowitz_pivots += 1;
                }

                // Scale pivot row so a[prow][col] = 1
                let prow_off = prow * n_cols;
                let pivot_coef = a[prow_off + col];
                let inv = pivot_coef.inv();
                for value in &mut a[prow_off..prow_off + n_cols] {
                    *value *= inv;
                }
                gf256_mul_slice(&mut b[prow], inv);

                // Copy pivot row into reusable buffers (no heap allocation)
                pivot_buf[..n_cols].copy_from_slice(&a[prow_off..prow_off + n_cols]);
                pivot_rhs[..symbol_size].copy_from_slice(&b[prow]);
                let sparse_cols = sparse_update_columns_if_beneficial(&pivot_buf[..n_cols], n_cols);

                // Eliminate column in all other rows.
                for (row, rhs) in b.iter_mut().enumerate().take(n_rows) {
                    if row == prow {
                        continue;
                    }
                    let row_off = row * n_cols;
                    let factor = a[row_off + col];
                    if factor.is_zero() {
                        continue;
                    }
                    if let Some(cols) = sparse_cols.as_ref() {
                        for &c in cols {
                            a[row_off + c] += factor * pivot_buf[c];
                        }
                    } else {
                        for c in 0..n_cols {
                            a[row_off + c] += factor * pivot_buf[c];
                        }
                    }
                    gf256_addmul_slice(rhs, &pivot_rhs[..symbol_size], factor);
                    gauss_ops += 1;
                }
            }

            if elimination_error.is_none() {
                if let Some(row) = first_inconsistent_dense_row(&a, n_rows, n_cols, &b) {
                    elimination_error = Some(inconsistent_matrix_error(&dense_rows, row));
                }
            }

            // Record work performed in this attempt, even if we fallback or fail.
            state.stats.pivots_selected += pivots_selected;
            state.stats.markowitz_pivots += markowitz_pivots;
            state.stats.gauss_ops += gauss_ops;

            if let Some(err) = elimination_error {
                if !hard_regime {
                    hard_regime = true;
                    state.stats.hard_regime_activated = true;
                    hard_plan = select_hard_regime_plan(n_rows, n_cols, &a);
                    state.stats.hard_regime_branch = Some(hard_plan.label());
                    state.stats.hard_regime_fallbacks += 1;
                    state.stats.hard_regime_conservative_fallback_reason =
                        Some("fallback_after_baseline_failure");
                    if let Some(base_b) = retry_rhs_snapshot.as_ref() {
                        rebuild_dense_matrix_from_equations(
                            &state.equations,
                            &dense_rows,
                            col_to_dense,
                            n_cols,
                            &mut a,
                        );
                        restore_dense_rhs(&mut b, base_b, symbol_size);
                    }
                    continue;
                }
                if matches!(hard_plan, HardRegimePlan::BlockSchurLowRank { .. }) {
                    hard_plan = HardRegimePlan::Markowitz;
                    state.stats.hard_regime_fallbacks += 1;
                    state.stats.hard_regime_conservative_fallback_reason =
                        Some("block_schur_failed_to_converge");
                    if let Some(base_b) = retry_rhs_snapshot.as_ref() {
                        rebuild_dense_matrix_from_equations(
                            &state.equations,
                            &dense_rows,
                            col_to_dense,
                            n_cols,
                            &mut a,
                        );
                        restore_dense_rhs(&mut b, base_b, symbol_size);
                    }
                    continue;
                }
                return Err(err);
            }
            break;
        }

        // Extract solutions: move RHS vectors instead of cloning
        for (dense_col, &col) in dense_cols.iter().enumerate() {
            let prow = pivot_row[dense_col];
            if prow < n_rows {
                state.solved[col] = Some(std::mem::take(&mut b[prow]));
            } else {
                state.solved[col] = Some(vec![0u8; symbol_size]);
            }
        }

        Ok(())
    }

    /// Generate the RFC 6330 tuple-derived equation (columns + coefficients) for a repair symbol.
    ///
    /// This must stay in parity with `SystematicEncoder::repair_symbol` so that
    /// decoder row construction exactly matches encoder repair bytes.
    #[must_use]
    pub fn repair_equation(&self, esi: u32) -> (Vec<usize>, Vec<Gf256>) {
        self.params.rfc_repair_equation(esi)
    }

    /// Generate the equation (columns + coefficients) using RFC 6330 tuple rules.
    ///
    /// This method computes tuple parameters from RFC 6330 Section 5.3.5.4 and
    /// expands them into intermediate symbol indices using Section 5.3.5.3.
    ///
    /// This is kept as an explicit alias used by RFC conformance tests.
    #[must_use]
    pub fn repair_equation_rfc6330(&self, esi: u32) -> (Vec<usize>, Vec<Gf256>) {
        self.repair_equation(esi)
    }

    /// Generate equations for all K source symbols.
    ///
    /// In systematic encoding, source symbol i maps directly to intermediate
    /// symbol i with no additional connections. This matches the encoder's
    /// `build_lt_rows` which simply sets `intermediate[i] = source[i]`.
    ///
    /// Returns a vector of K equations, where index i is the equation for
    /// source ESI i.
    #[must_use]
    pub fn all_source_equations(&self) -> Vec<(Vec<usize>, Vec<Gf256>)> {
        let k = self.params.k;

        // Systematic encoding: source symbol i maps directly to intermediate[i]
        // No additional LT connections - the encoder's build_lt_rows just does
        // matrix.set(row, i, Gf256::ONE) for each source symbol.
        (0..k).map(|i| (vec![i], vec![Gf256::ONE])).collect()
    }

    /// Get the equation for a specific source symbol ESI.
    ///
    /// In systematic encoding, source symbol `esi` maps directly to
    /// intermediate symbol `esi` with coefficient 1.
    #[must_use]
    pub fn source_equation(&self, esi: u32) -> (Vec<usize>, Vec<Gf256>) {
        assert!((esi as usize) < self.params.k, "source ESI must be < K");
        // Systematic: source[esi] = intermediate[esi]
        (vec![esi as usize], vec![Gf256::ONE])
    }
}

fn first_mismatch_byte(expected: &[u8], actual: &[u8]) -> Option<usize> {
    expected
        .iter()
        .zip(actual.iter())
        .position(|(expected, actual)| expected != actual)
}

fn rebuild_dense_matrix_from_equations(
    equations: &[Equation],
    dense_rows: &[usize],
    col_to_dense: &DenseColIndexMap,
    n_cols: usize,
    a: &mut [Gf256],
) {
    a.fill(Gf256::ZERO);
    for (row, &eq_idx) in dense_rows.iter().enumerate() {
        let row_off = row * n_cols;
        for &(col, coef) in &equations[eq_idx].terms {
            if let Some(dense_col) = dense_col_index(col_to_dense, col) {
                a[row_off + dense_col] = coef;
            }
        }
    }
}

fn snapshot_dense_rhs(rows: &[Vec<u8>], symbol_size: usize) -> Vec<u8> {
    let mut snapshot = vec![0u8; rows.len().saturating_mul(symbol_size)];
    for (row_idx, row) in rows.iter().enumerate() {
        debug_assert_eq!(row.len(), symbol_size);
        let off = row_idx * symbol_size;
        snapshot[off..off + symbol_size].copy_from_slice(row);
    }
    snapshot
}

fn restore_dense_rhs(rows: &mut [Vec<u8>], snapshot: &[u8], symbol_size: usize) {
    debug_assert_eq!(snapshot.len(), rows.len().saturating_mul(symbol_size));
    for (row_idx, row) in rows.iter_mut().enumerate() {
        debug_assert_eq!(row.len(), symbol_size);
        let off = row_idx * symbol_size;
        row.copy_from_slice(&snapshot[off..off + symbol_size]);
    }
}

// ============================================================================
// Helper: build ReceivedSymbol from raw data
// ============================================================================

impl ReceivedSymbol {
    /// Create a source symbol (ESI < K).
    #[must_use]
    pub fn source(esi: u32, data: Vec<u8>) -> Self {
        Self {
            esi,
            is_source: true,
            columns: vec![esi as usize],
            coefficients: vec![Gf256::ONE],
            data,
        }
    }

    /// Create a repair symbol with precomputed equation.
    #[must_use]
    pub fn repair(esi: u32, columns: Vec<usize>, coefficients: Vec<Gf256>, data: Vec<u8>) -> Self {
        Self {
            esi,
            is_source: false,
            columns,
            coefficients,
            data,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dense_col_index_map_handles_sparse_columns() {
        let unsolved = vec![2, 7, 11];
        let col_to_dense = build_dense_col_index_map(&unsolved);

        assert_eq!(dense_col_index(&col_to_dense, 2), Some(0));
        assert_eq!(dense_col_index(&col_to_dense, 7), Some(1));
        assert_eq!(dense_col_index(&col_to_dense, 11), Some(2));
        assert_eq!(dense_col_index(&col_to_dense, 3), None);
        assert_eq!(dense_col_index(&col_to_dense, 99), None);
    }

    #[test]
    fn sparse_first_dense_columns_orders_by_support_then_column() {
        let equations = vec![
            Equation::new(vec![7, 11], vec![Gf256::ONE, Gf256::ONE]),
            Equation::new(vec![2, 7], vec![Gf256::ONE, Gf256::ONE]),
            Equation::new(vec![7], vec![Gf256::ONE]),
            Equation::new(vec![2], vec![Gf256::ONE]),
        ];
        let dense_rows = vec![0, 1, 2, 3];
        let unsolved = vec![7, 2, 11];

        let ordered = sparse_first_dense_columns(&equations, &dense_rows, &unsolved);

        // supports: col 11 -> 1, col 2 -> 2, col 7 -> 3
        assert_eq!(ordered, vec![11, 2, 7]);
    }

    #[test]
    fn sparse_first_dense_columns_sorted_fast_path_matches_expected() {
        let equations = vec![
            Equation::new(vec![7, 11], vec![Gf256::ONE, Gf256::ONE]),
            Equation::new(vec![2, 7], vec![Gf256::ONE, Gf256::ONE]),
            Equation::new(vec![7], vec![Gf256::ONE]),
            Equation::new(vec![2], vec![Gf256::ONE]),
        ];
        let dense_rows = vec![0, 1, 2, 3];
        let unsolved = vec![2, 7, 11];

        let ordered = sparse_first_dense_columns(&equations, &dense_rows, &unsolved);

        // supports: col 11 -> 1, col 2 -> 2, col 7 -> 3
        assert_eq!(ordered, vec![11, 2, 7]);
    }

    #[test]
    fn dense_col_index_map_uses_direct_representation_for_compact_range() {
        let unsolved = vec![1, 2, 4];
        let map = build_dense_col_index_map(&unsolved);

        assert!(matches!(map, DenseColIndexMap::Direct(_)));
        assert_eq!(dense_col_index(&map, 1), Some(0));
        assert_eq!(dense_col_index(&map, 2), Some(1));
        assert_eq!(dense_col_index(&map, 4), Some(2));
        assert_eq!(dense_col_index(&map, 3), None);
    }

    #[test]
    fn dense_col_index_map_uses_sorted_pairs_for_sparse_high_columns() {
        let unsolved = vec![2, 7, 10_000];
        let map = build_dense_col_index_map(&unsolved);

        assert!(matches!(map, DenseColIndexMap::SortedPairs(_)));
        assert_eq!(dense_col_index(&map, 2), Some(0));
        assert_eq!(dense_col_index(&map, 7), Some(1));
        assert_eq!(dense_col_index(&map, 10_000), Some(2));
        assert_eq!(dense_col_index(&map, 9_999), None);
    }

    #[test]
    fn dense_factor_signature_detects_equation_changes() {
        let equations_a = vec![Equation::new(vec![0, 1], vec![Gf256::ONE, Gf256::new(7)])];
        let equations_b = vec![Equation::new(vec![0, 1], vec![Gf256::ONE, Gf256::new(9)])];
        let dense_rows = vec![0];
        let unsolved = vec![0, 1];

        let sig_a = DenseFactorSignature::from_equations(&equations_a, &dense_rows, &unsolved);
        let sig_b = DenseFactorSignature::from_equations(&equations_b, &dense_rows, &unsolved);

        assert_ne!(sig_a, sig_b);
    }

    #[test]
    fn dense_factor_cache_requires_strict_signature_match() {
        let equations_a = vec![Equation::new(vec![0, 1], vec![Gf256::ONE, Gf256::new(7)])];
        let equations_b = vec![Equation::new(vec![0, 1], vec![Gf256::ONE, Gf256::new(9)])];
        let dense_rows = vec![0];
        let unsolved = vec![0, 1];

        let sig_a = DenseFactorSignature::from_equations(&equations_a, &dense_rows, &unsolved);
        let sig_b = DenseFactorSignature::from_equations(&equations_b, &dense_rows, &unsolved);

        let mut cache = DenseFactorCache::default();
        assert_eq!(
            cache.insert(
                sig_a.clone(),
                Arc::new(DenseFactorArtifact::new(vec![1, 0]))
            ),
            DenseFactorCacheResult::MissInserted
        );
        assert_eq!(
            cache.lookup(&sig_a),
            DenseFactorCacheLookup::Hit(Arc::new(DenseFactorArtifact::new(vec![1, 0])))
        );
        assert_eq!(cache.lookup(&sig_b), DenseFactorCacheLookup::MissNoEntry);
    }

    #[test]
    fn dense_factor_cache_detects_fingerprint_collision() {
        let equations_a = vec![Equation::new(vec![0, 1], vec![Gf256::ONE, Gf256::new(7)])];
        let equations_b = vec![Equation::new(vec![0, 1], vec![Gf256::ONE, Gf256::new(9)])];
        let dense_rows = vec![0];
        let unsolved = vec![0, 1];

        let sig_a = DenseFactorSignature::from_equations(&equations_a, &dense_rows, &unsolved);
        let mut sig_b = DenseFactorSignature::from_equations(&equations_b, &dense_rows, &unsolved);
        sig_b.fingerprint = sig_a.fingerprint;

        let mut cache = DenseFactorCache::default();
        assert_eq!(
            cache.insert(sig_a, Arc::new(DenseFactorArtifact::new(vec![1, 0]))),
            DenseFactorCacheResult::MissInserted
        );
        assert_eq!(
            cache.lookup(&sig_b),
            DenseFactorCacheLookup::MissFingerprintCollision
        );
    }

    #[test]
    fn dense_factor_cache_evicts_oldest_entry_at_capacity() {
        let mut cache = DenseFactorCache::default();
        let mut first_signature = None;

        for idx in 0..=DENSE_FACTOR_CACHE_CAPACITY {
            let signature = DenseFactorSignature {
                fingerprint: idx as u64,
                unsolved: vec![idx],
                row_offsets: vec![1],
                row_terms_flat: vec![(idx, 1)],
            };
            if idx == 0 {
                first_signature = Some(signature.clone());
            }
            let expected = if idx + 1 > DENSE_FACTOR_CACHE_CAPACITY {
                DenseFactorCacheResult::MissEvicted
            } else {
                DenseFactorCacheResult::MissInserted
            };
            assert_eq!(
                cache.insert(signature, Arc::new(DenseFactorArtifact::new(vec![idx]))),
                expected
            );
        }

        assert_eq!(cache.len(), DENSE_FACTOR_CACHE_CAPACITY);
        assert_eq!(
            cache.lookup(&first_signature.expect("first signature recorded")),
            DenseFactorCacheLookup::MissNoEntry
        );
    }

    #[test]
    fn hybrid_cost_model_prefers_sparse_for_low_support() {
        assert!(should_use_sparse_row_update(3, 8));
        assert!(should_use_sparse_row_update(6, 10));
        assert!(!should_use_sparse_row_update(7, 10));
        assert!(!should_use_sparse_row_update(1, 0));
    }

    #[test]
    fn pivot_nonzero_columns_returns_stable_sorted_positions() {
        let row = vec![
            Gf256::ZERO,
            Gf256::ONE,
            Gf256::ZERO,
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ZERO,
        ];
        let cols = pivot_nonzero_columns(&row, row.len());
        assert_eq!(cols, vec![1, 3, 4]);
    }

    #[test]
    fn sparse_update_columns_if_beneficial_matches_threshold() {
        // For n_cols=10 and ratio 3/5, sparse path should accept up to 6 non-zero entries.
        let row_sparse = vec![
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ZERO,
            Gf256::ONE,
            Gf256::ZERO,
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ZERO,
            Gf256::ZERO,
        ];
        let row_dense = vec![
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ONE,
            Gf256::ZERO,
            Gf256::ZERO,
            Gf256::ZERO,
        ];

        let sparse_cols = sparse_update_columns_if_beneficial(&row_sparse, 10)
            .expect("row_sparse should take sparse update path");
        assert_eq!(sparse_cols, vec![0, 1, 3, 5, 6, 7]);
        assert!(sparse_update_columns_if_beneficial(&row_dense, 10).is_none());
    }

    #[test]
    fn hard_regime_plan_selects_block_schur_for_dense_large_core() {
        let n_rows = 12;
        let n_cols = 12;
        let dense = vec![Gf256::ONE; n_rows * n_cols];
        let plan = select_hard_regime_plan(n_rows, n_cols, &dense);
        assert_eq!(
            plan,
            HardRegimePlan::BlockSchurLowRank { split_col: 8 },
            "dense 12x12 system should select deterministic block-schur plan"
        );
    }

    #[test]
    fn should_activate_hard_regime_for_dense_matrix() {
        let n_rows = 8;
        let n_cols = 8;
        let dense = vec![Gf256::ONE; n_rows * n_cols];
        assert!(should_activate_hard_regime(n_rows, n_cols, &dense));
    }

    #[test]
    fn should_not_activate_hard_regime_for_small_matrix() {
        let n_rows = 4;
        let n_cols = 4;
        let sparse = vec![Gf256::ZERO; n_rows * n_cols];
        assert!(!should_activate_hard_regime(n_rows, n_cols, &sparse));
    }

    #[test]
    fn failure_classification_is_explicit() {
        assert!(
            DecodeError::InsufficientSymbols {
                received: 1,
                required: 2
            }
            .is_recoverable()
        );
        assert!(DecodeError::SingularMatrix { row: 3 }.is_recoverable());
        assert!(
            DecodeError::SymbolSizeMismatch {
                expected: 8,
                actual: 7
            }
            .is_unrecoverable()
        );
        assert!(
            DecodeError::ColumnIndexOutOfRange {
                esi: 1,
                column: 99,
                max_valid: 12
            }
            .is_unrecoverable()
        );
        assert!(
            DecodeError::CorruptDecodedOutput {
                esi: 1,
                byte_index: 0,
                expected: 1,
                actual: 2
            }
            .is_unrecoverable()
        );
    }

    #[test]
    fn decoder_policy_budget_exhaustion_forces_conservative_baseline() {
        let n_rows = 65;
        let n_cols = 65;
        let dense = vec![Gf256::ONE; n_rows * n_cols];
        let decision = choose_runtime_decoder_policy(n_rows, n_cols, dense.len(), 0, 700);
        assert_eq!(decision.mode, DecoderPolicyMode::ConservativeBaseline);
        assert_eq!(decision.reason, "policy_budget_exhausted_conservative");
        assert!(decision.features.budget_exhausted);
    }

    #[test]
    fn decoder_policy_prefers_aggressive_strategy_for_dense_high_pressure() {
        let n_rows = 16;
        let n_cols = 16;
        let dense = vec![Gf256::ONE; n_rows * n_cols];
        let decision = choose_runtime_decoder_policy(n_rows, n_cols, dense.len(), 0, 850);
        assert!(
            matches!(
                decision.mode,
                DecoderPolicyMode::HighSupportFirst | DecoderPolicyMode::BlockSchurLowRank
            ),
            "dense/high-pressure matrix should avoid conservative baseline"
        );
    }

    #[test]
    fn decoder_policy_prefers_conservative_for_sparse_low_pressure() {
        let n_rows = 24;
        let n_cols = 16;

        let one = choose_runtime_decoder_policy(n_rows, n_cols, n_cols, 0, 40);
        let two = choose_runtime_decoder_policy(n_rows, n_cols, n_cols, 0, 40);
        assert_eq!(one, two, "policy decision should be deterministic");
        assert_eq!(one.mode, DecoderPolicyMode::ConservativeBaseline);
        assert_eq!(one.reason, "expected_loss_conservative_gate");
    }

    #[test]
    fn all_source_equations_returns_identity_map() {
        let k = 8;
        let decoder = InactivationDecoder::new(k, 32, 42);
        let equations = decoder.all_source_equations();

        assert_eq!(equations.len(), k, "should return exactly K equations");
        for (i, (cols, coefs)) in equations.iter().enumerate() {
            assert_eq!(cols, &[i], "source equation {i} should map to column {i}");
            assert_eq!(
                coefs,
                &[Gf256::ONE],
                "source equation {i} should have unit coefficient"
            );
        }
    }

    #[test]
    fn source_equation_matches_all_source_equations() {
        let k = 12;
        let decoder = InactivationDecoder::new(k, 16, 99);
        let all = decoder.all_source_equations();

        for esi in 0..k as u32 {
            let single = decoder.source_equation(esi);
            assert_eq!(
                single, all[esi as usize],
                "source_equation({esi}) must match all_source_equations()[{esi}]"
            );
        }
    }

    #[test]
    #[should_panic(expected = "source ESI must be < K")]
    fn source_equation_panics_on_esi_ge_k() {
        let k = 4;
        let decoder = InactivationDecoder::new(k, 16, 42);
        let _ = decoder.source_equation(k as u32); // ESI == K should panic
    }

    #[test]
    fn equation_merge_deduplicates_and_sorts() {
        // Two entries for the same column should merge (XOR coefficients)
        let eq = Equation::new(vec![3, 1, 3], vec![Gf256::ONE, Gf256::new(5), Gf256::ONE]);
        // col 3: ONE + ONE = ZERO (removed), col 1: 5
        assert_eq!(eq.degree(), 1);
        assert_eq!(eq.terms[0].0, 1);
        assert_eq!(eq.terms[0].1, Gf256::new(5));
    }

    #[test]
    fn equation_coef_returns_correct_coefficient() {
        let eq = Equation::new(
            vec![0, 5, 10],
            vec![Gf256::ONE, Gf256::new(7), Gf256::new(3)],
        );
        assert_eq!(eq.coef(0), Gf256::ONE);
        assert_eq!(eq.coef(5), Gf256::new(7));
        assert_eq!(eq.coef(10), Gf256::new(3));
        assert_eq!(eq.coef(3), Gf256::ZERO);
        assert_eq!(eq.coef(99), Gf256::ZERO);
    }

    #[test]
    fn received_symbol_source_builder() {
        let sym = ReceivedSymbol::source(3, vec![0xAA; 16]);
        assert!(sym.is_source);
        assert_eq!(sym.esi, 3);
        assert_eq!(sym.columns, vec![3]);
        assert_eq!(sym.coefficients, vec![Gf256::ONE]);
        assert_eq!(sym.data.len(), 16);
    }

    #[test]
    fn received_symbol_repair_builder() {
        let sym = ReceivedSymbol::repair(
            10,
            vec![0, 2, 5],
            vec![Gf256::ONE, Gf256::new(3), Gf256::ONE],
            vec![0xBB; 8],
        );
        assert!(!sym.is_source);
        assert_eq!(sym.esi, 10);
        assert_eq!(sym.columns, vec![0, 2, 5]);
        assert_eq!(sym.data.len(), 8);
    }

    #[test]
    fn det_hasher_is_deterministic() {
        let mut h1 = DetHasher::default();
        let mut h2 = DetHasher::default();
        h1.write(&[1, 2, 3, 4]);
        h2.write(&[1, 2, 3, 4]);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn det_hasher_differs_for_different_input() {
        let mut h1 = DetHasher::default();
        let mut h2 = DetHasher::default();
        h1.write(&[1, 2, 3]);
        h2.write(&[4, 5, 6]);
        assert_ne!(h1.finish(), h2.finish());
    }

    // ── Security regression: checked_mul overflow guard (1fcd949) ──

    #[test]
    fn insufficient_symbols_error_is_recoverable() {
        // The checked_mul guard returns InsufficientSymbols on overflow.
        // Verify this error variant is classified as recoverable so callers
        // can retry with more symbols rather than treating it as fatal.
        let err = DecodeError::InsufficientSymbols {
            received: usize::MAX,
            required: usize::MAX,
        };
        assert!(err.is_recoverable());
    }

    #[test]
    fn decode_error_display_insufficient_symbols() {
        let err = DecodeError::InsufficientSymbols {
            received: 5,
            required: 10,
        };
        let msg = err.to_string();
        assert!(msg.contains('5'), "should mention received count");
        assert!(msg.contains("10"), "should mention required count");
    }
}
