//! GF(256) finite-field arithmetic for RaptorQ encoding/decoding.
//!
//! Implements the Galois field GF(2^8) used by RFC 6330 (RaptorQ) with the
//! irreducible polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x1D over GF(2)).
//!
//! # Representation
//!
//! Elements are stored as `u8` values where each bit represents a coefficient
//! of a degree-7 polynomial over GF(2). Addition is XOR; multiplication uses
//! precomputed log/exp (antilog) tables for O(1) operations.
//!
//! # Determinism
//!
//! All operations are deterministic and platform-independent. Table generation
//! is `const`-evaluated at compile time.
//!
//! # Safety
//!
//! This module is scalar-only and contains no unsafe code.

// Safety: no unsafe code. The crate-level #![forbid(unsafe_code)] enforces this.

/// The irreducible polynomial x^8 + x^4 + x^3 + x^2 + 1.
///
/// Represented as 0x1D (the low 8 bits after subtracting x^8).
/// Full polynomial is 0x11D but we only need the reduction mask.
const POLY: u16 = 0x1D;

/// A primitive element (generator) of GF(256). The value 2 (i.e. x)
/// generates the full multiplicative group of order 255.
const GENERATOR: u16 = 0x02;

/// Logarithm table: `LOG[a]` = discrete log base `GENERATOR` of `a`.
///
/// `LOG[0]` is unused (log of zero is undefined); set to 0 by convention.
static LOG: [u8; 256] = build_log_table();

/// Exponential (antilog) table: `EXP[i]` = `GENERATOR^i mod POLY`.
///
/// Extended to 512 entries so that `EXP[a + b]` works without modular
/// reduction for any `a, b < 255`.
static EXP: [u8; 512] = build_exp_table();

// ============================================================================
// Table generation (const)
// ============================================================================

const fn build_exp_table() -> [u8; 512] {
    let mut table = [0u8; 512];
    let mut val: u16 = 1;
    let mut i = 0usize;
    while i < 255 {
        table[i] = val as u8;
        table[i + 255] = val as u8; // mirror for mod-free lookup
        val <<= 1;
        if val & 0x100 != 0 {
            val ^= 0x100 | POLY;
        }
        i += 1;
    }
    // EXP[255] = EXP[0] = 1 (wraps), already set by mirror
    table[255] = 1;
    table[510] = 1;
    table
}

const fn build_log_table() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut val: u16 = 1;
    let mut i = 0u8;
    // We loop 255 times (exponents 0..254) to fill log for all non-zero elements.
    loop {
        table[val as usize] = i;
        val <<= 1;
        if val & 0x100 != 0 {
            val ^= 0x100 | POLY;
        }
        if i == 254 {
            break;
        }
        i += 1;
    }
    table
}

const fn gf256_mul_const(mut a: u8, mut b: u8) -> u8 {
    let mut acc = 0u8;
    let mut i = 0u8;
    while i < 8 {
        if (b & 1) != 0 {
            acc ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= POLY as u8;
        }
        b >>= 1;
        i += 1;
    }
    acc
}

#[allow(clippy::large_stack_arrays)]
const fn build_mul_tables() -> [[u8; 256]; 256] {
    let mut tables = [[0u8; 256]; 256];
    let mut c = 0usize;
    while c < 256 {
        let mut x = 0usize;
        while x < 256 {
            tables[c][x] = gf256_mul_const(x as u8, c as u8);
            x += 1;
        }
        c += 1;
    }
    tables
}

static MUL_TABLES: [[u8; 256]; 256] = build_mul_tables();

/// Placeholder for the SIMD nibble-table type. In this scalar-only build
/// the struct carries no data; it exists so that call sites compile without
/// conditional compilation.
struct NibbleTables;

impl NibbleTables {
    #[inline]
    fn for_scalar(_c: Gf256) -> Self {
        Self
    }
}

// ============================================================================
// Field element wrapper
// ============================================================================

/// An element of GF(256).
///
/// Wraps a `u8` and provides field arithmetic operations. All operations
/// are constant-time with respect to the element value (table lookups).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct Gf256(pub u8);

impl Gf256 {
    /// The additive identity (zero element).
    pub const ZERO: Self = Self(0);

    /// The multiplicative identity (one element).
    pub const ONE: Self = Self(1);

    /// The primitive element (generator of the multiplicative group).
    pub const ALPHA: Self = Self(GENERATOR as u8);

    /// Creates a field element from a raw byte.
    #[inline]
    #[must_use]
    pub const fn new(val: u8) -> Self {
        Self(val)
    }

    /// Returns the raw byte value.
    #[inline]
    #[must_use]
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// Returns true if this is the zero element.
    #[inline]
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Field addition (XOR).
    #[inline]
    #[must_use]
    pub const fn add(self, rhs: Self) -> Self {
        Self(self.0 ^ rhs.0)
    }

    /// Field subtraction (same as addition in characteristic 2).
    #[inline]
    #[must_use]
    pub const fn sub(self, rhs: Self) -> Self {
        self.add(rhs)
    }

    /// Field multiplication using log/exp tables.
    ///
    /// Returns `ZERO` if either operand is zero.
    #[inline]
    #[must_use]
    pub fn mul_field(self, rhs: Self) -> Self {
        if self.0 == 0 || rhs.0 == 0 {
            return Self::ZERO;
        }
        let log_sum = LOG[self.0 as usize] as usize + LOG[rhs.0 as usize] as usize;
        Self(EXP[log_sum])
    }

    /// Multiplicative inverse.
    ///
    /// # Panics
    ///
    /// Panics if `self` is zero (zero has no multiplicative inverse).
    #[inline]
    #[must_use]
    pub fn inv(self) -> Self {
        assert!(!self.is_zero(), "cannot invert zero in GF(256)");
        // inv(a) = a^254 = EXP[255 - LOG[a]]
        let log_a = LOG[self.0 as usize] as usize;
        Self(EXP[255 - log_a])
    }

    /// Field division: `self / rhs`.
    ///
    /// # Panics
    ///
    /// Panics if `rhs` is zero.
    #[inline]
    #[must_use]
    pub fn div_field(self, rhs: Self) -> Self {
        self.mul_field(rhs.inv())
    }

    /// Exponentiation: `self^exp` using the log/exp tables.
    ///
    /// Returns `ONE` for any base raised to the zero power.
    /// Returns `ZERO` for zero raised to any positive power.
    #[must_use]
    pub fn pow(self, exp: u8) -> Self {
        if exp == 0 {
            return Self::ONE;
        }
        if self.is_zero() {
            return Self::ZERO;
        }
        let log_a = u32::from(LOG[self.0 as usize]);
        let log_result = (log_a * u32::from(exp)) % 255;
        Self(EXP[log_result as usize])
    }
}

impl core::fmt::Debug for Gf256 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "GF({})", self.0)
    }
}

impl core::fmt::Display for Gf256 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl core::ops::Add for Gf256 {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self {
        Self::add(self, rhs)
    }
}

impl core::ops::Sub for Gf256 {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Self::sub(self, rhs)
    }
}

impl core::ops::Mul for Gf256 {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: Self) -> Self {
        Self::mul_field(self, rhs)
    }
}

impl core::ops::Div for Gf256 {
    type Output = Self;
    #[inline]
    fn div(self, rhs: Self) -> Self {
        Self::div_field(self, rhs)
    }
}

impl core::ops::AddAssign for Gf256 {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        *self = Self::add(*self, rhs);
    }
}

impl core::ops::SubAssign for Gf256 {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        *self = Self::sub(*self, rhs);
    }
}

impl core::ops::MulAssign for Gf256 {
    #[inline]
    fn mul_assign(&mut self, rhs: Self) {
        *self = Self::mul_field(*self, rhs);
    }
}

// ============================================================================
// Bulk operations on byte slices (symbol-level XOR + scale)
// ============================================================================

/// Minimum slice length to amortize wide-loop setup in mul paths.
const MUL_TABLE_THRESHOLD: usize = 64;
/// Minimum slice length to amortize wide-loop setup in addmul paths.
const ADDMUL_TABLE_THRESHOLD: usize = 64;

#[inline]
fn mul_table_for(c: Gf256) -> &'static [u8; 256] {
    &MUL_TABLES[c.0 as usize]
}

/// XOR `src` into `dst` element-wise: `dst[i] ^= src[i]`.
///
/// Uses 32-byte-wide XOR (4x u64) for throughput on bulk data, falling back
/// to 8-byte and scalar loops for the tail.
///
/// # Panics
///
/// Panics if `src.len() != dst.len()`.
#[inline]
pub fn gf256_add_slice(dst: &mut [u8], src: &[u8]) {
    gf256_add_slice_scalar(dst, src);
}

/// XOR two independent source/destination pairs.
///
/// Applies:
/// - `dst1[i] ^= src1[i]`
/// - `dst2[i] ^= src2[i]`
///
/// # Panics
///
/// Panics if `dst1.len() != src1.len()` or `dst2.len() != src2.len()`.
#[inline]
pub fn gf256_add_slices2(dst1: &mut [u8], src1: &[u8], dst2: &mut [u8], src2: &[u8]) {
    assert_eq!(dst1.len(), src1.len(), "slice length mismatch");
    assert_eq!(dst2.len(), src2.len(), "slice length mismatch");
    gf256_add_slice_scalar(dst1, src1);
    gf256_add_slice_scalar(dst2, src2);
}

/// Multiply every element of `dst` by scalar `c` in GF(256).
///
/// For slices >= `MUL_TABLE_THRESHOLD` bytes, a pre-built 256-entry table
/// replaces per-element branch+double-lookup with a single table lookup.
///
/// If `c` is zero, the entire slice is zeroed. If `c` is one, this is a no-op.
#[inline]
pub fn gf256_mul_slice(dst: &mut [u8], c: Gf256) {
    gf256_mul_slice_scalar(dst, c);
}

/// Multiply two slices by (possibly different) scalars.
///
/// Applies: `dst1[i] *= c1` and `dst2[i] *= c2`.
#[inline]
pub fn gf256_mul_slices2(dst1: &mut [u8], c1: Gf256, dst2: &mut [u8], c2: Gf256) {
    gf256_mul_slice_scalar(dst1, c1);
    gf256_mul_slice_scalar(dst2, c2);
}

/// Multiply-accumulate: `dst[i] += c * src[i]` in GF(256).
///
/// For slices >= `ADDMUL_TABLE_THRESHOLD` bytes the hot path uses wide table
/// kernels. Smaller slices use scalar table lookups.
///
/// # Panics
///
/// Panics if `src.len() != dst.len()`.
#[inline]
pub fn gf256_addmul_slice(dst: &mut [u8], src: &[u8], c: Gf256) {
    gf256_addmul_slice_scalar(dst, src, c);
}

/// Multiply-accumulate two independent pairs using (possibly different) scalars.
///
/// Applies:
/// - `dst1[i] += c1 * src1[i]`
/// - `dst2[i] += c2 * src2[i]`
///
/// # Panics
///
/// Panics if `dst1.len() != src1.len()` or `dst2.len() != src2.len()`.
#[inline]
pub fn gf256_addmul_slices2(
    dst1: &mut [u8],
    src1: &[u8],
    c1: Gf256,
    dst2: &mut [u8],
    src2: &[u8],
    c2: Gf256,
) {
    assert_eq!(dst1.len(), src1.len(), "slice length mismatch");
    assert_eq!(dst2.len(), src2.len(), "slice length mismatch");
    gf256_addmul_slice_scalar(dst1, src1, c1);
    gf256_addmul_slice_scalar(dst2, src2, c2);
}

// ============================================================================
// Scalar inner kernels
// ============================================================================

fn gf256_add_slice_scalar(dst: &mut [u8], src: &[u8]) {
    assert_eq!(dst.len(), src.len(), "slice length mismatch");

    // Wide path: 32 bytes (4x u64) per iteration.
    let mut d_chunks = dst.chunks_exact_mut(32);
    let mut s_chunks = src.chunks_exact(32);
    for (d_chunk, s_chunk) in d_chunks.by_ref().zip(s_chunks.by_ref()) {
        let mut d_words = [
            u64::from_ne_bytes(d_chunk[0..8].try_into().unwrap()),
            u64::from_ne_bytes(d_chunk[8..16].try_into().unwrap()),
            u64::from_ne_bytes(d_chunk[16..24].try_into().unwrap()),
            u64::from_ne_bytes(d_chunk[24..32].try_into().unwrap()),
        ];
        let s_words = [
            u64::from_ne_bytes(s_chunk[0..8].try_into().unwrap()),
            u64::from_ne_bytes(s_chunk[8..16].try_into().unwrap()),
            u64::from_ne_bytes(s_chunk[16..24].try_into().unwrap()),
            u64::from_ne_bytes(s_chunk[24..32].try_into().unwrap()),
        ];
        d_words[0] ^= s_words[0];
        d_words[1] ^= s_words[1];
        d_words[2] ^= s_words[2];
        d_words[3] ^= s_words[3];
        d_chunk[0..8].copy_from_slice(&d_words[0].to_ne_bytes());
        d_chunk[8..16].copy_from_slice(&d_words[1].to_ne_bytes());
        d_chunk[16..24].copy_from_slice(&d_words[2].to_ne_bytes());
        d_chunk[24..32].copy_from_slice(&d_words[3].to_ne_bytes());
    }

    // 8-byte tail.
    let d_rem = d_chunks.into_remainder();
    let s_rem = s_chunks.remainder();
    let mut d8 = d_rem.chunks_exact_mut(8);
    let mut s8 = s_rem.chunks_exact(8);
    for (d_chunk, s_chunk) in d8.by_ref().zip(s8.by_ref()) {
        let d_arr: [u8; 8] = d_chunk.try_into().unwrap();
        let s_arr: [u8; 8] = s_chunk.try_into().unwrap();
        let result = u64::from_ne_bytes(d_arr) ^ u64::from_ne_bytes(s_arr);
        d_chunk.copy_from_slice(&result.to_ne_bytes());
    }

    // Scalar tail.
    for (d, s) in d8.into_remainder().iter_mut().zip(s8.remainder()) {
        *d ^= s;
    }
}

fn gf256_mul_slice_scalar(dst: &mut [u8], c: Gf256) {
    if c.is_zero() {
        dst.fill(0);
        return;
    }
    if c == Gf256::ONE {
        return;
    }
    let table = mul_table_for(c);
    if dst.len() >= MUL_TABLE_THRESHOLD {
        let nib = NibbleTables::for_scalar(c);
        mul_with_table_wide(dst, &nib, table);
    } else {
        mul_with_table_scalar(dst, table);
    }
}

fn gf256_addmul_slice_scalar(dst: &mut [u8], src: &[u8], c: Gf256) {
    assert_eq!(dst.len(), src.len(), "slice length mismatch");
    if c.is_zero() {
        return;
    }
    if c == Gf256::ONE {
        gf256_add_slice_scalar(dst, src);
        return;
    }
    let table = mul_table_for(c);
    if src.len() >= ADDMUL_TABLE_THRESHOLD {
        let nib = NibbleTables::for_scalar(c);
        addmul_with_table_wide(dst, src, &nib, table);
        return;
    }
    addmul_with_table_scalar(dst, src, table);
}

// ============================================================================
// Table-driven inner loops (scalar / wide)
// ============================================================================

/// Wide table-driven inner loop for `gf256_mul_slice`.
///
/// Processes 8 bytes per iteration to amortize loop overhead.
fn mul_with_table_wide(dst: &mut [u8], _nib: &NibbleTables, table: &[u8; 256]) {
    let mut chunks = dst.chunks_exact_mut(8);
    for chunk in chunks.by_ref() {
        let mapped = [
            table[chunk[0] as usize],
            table[chunk[1] as usize],
            table[chunk[2] as usize],
            table[chunk[3] as usize],
            table[chunk[4] as usize],
            table[chunk[5] as usize],
            table[chunk[6] as usize],
            table[chunk[7] as usize],
        ];
        chunk.copy_from_slice(&mapped);
    }
    for d in chunks.into_remainder() {
        *d = table[*d as usize];
    }
}

/// Table-driven scalar inner loop for `gf256_mul_slice`.
///
/// Used by the production scalar path for short slices and by tests as the
/// scalar reference against the wide table kernel.
fn mul_with_table_scalar(dst: &mut [u8], table: &[u8; 256]) {
    let mut chunks = dst.chunks_exact_mut(8);
    for chunk in chunks.by_ref() {
        let t = [
            table[chunk[0] as usize],
            table[chunk[1] as usize],
            table[chunk[2] as usize],
            table[chunk[3] as usize],
            table[chunk[4] as usize],
            table[chunk[5] as usize],
            table[chunk[6] as usize],
            table[chunk[7] as usize],
        ];
        chunk.copy_from_slice(&t);
    }
    for d in chunks.into_remainder() {
        *d = table[*d as usize];
    }
}

/// Wide table-driven inner loop for `gf256_addmul_slice`.
///
/// Processes 8 bytes per iteration, XORing the products into `dst`.
fn addmul_with_table_wide(dst: &mut [u8], src: &[u8], _nib: &NibbleTables, table: &[u8; 256]) {
    let mut d_chunks = dst.chunks_exact_mut(8);
    let mut s_chunks = src.chunks_exact(8);
    for (d_chunk, s_chunk) in d_chunks.by_ref().zip(s_chunks.by_ref()) {
        let d_word = u64::from_ne_bytes(d_chunk[..].try_into().unwrap());
        let s_word = u64::from_ne_bytes([
            table[s_chunk[0] as usize],
            table[s_chunk[1] as usize],
            table[s_chunk[2] as usize],
            table[s_chunk[3] as usize],
            table[s_chunk[4] as usize],
            table[s_chunk[5] as usize],
            table[s_chunk[6] as usize],
            table[s_chunk[7] as usize],
        ]);
        d_chunk.copy_from_slice(&(d_word ^ s_word).to_ne_bytes());
    }
    for (d, s) in d_chunks
        .into_remainder()
        .iter_mut()
        .zip(s_chunks.remainder())
    {
        *d ^= table[*s as usize];
    }
}

/// Table-driven scalar inner loop for `gf256_addmul_slice`.
///
/// Used by the production scalar path for short slices and by tests as the
/// scalar reference against the wide table kernel.
fn addmul_with_table_scalar(dst: &mut [u8], src: &[u8], table: &[u8; 256]) {
    let mut d_chunks = dst.chunks_exact_mut(8);
    let mut s_chunks = src.chunks_exact(8);
    for (d_chunk, s_chunk) in d_chunks.by_ref().zip(s_chunks.by_ref()) {
        let t = [
            table[s_chunk[0] as usize],
            table[s_chunk[1] as usize],
            table[s_chunk[2] as usize],
            table[s_chunk[3] as usize],
            table[s_chunk[4] as usize],
            table[s_chunk[5] as usize],
            table[s_chunk[6] as usize],
            table[s_chunk[7] as usize],
        ];
        let d_arr: [u8; 8] = d_chunk[..].try_into().unwrap();
        let result = u64::from_ne_bytes(d_arr) ^ u64::from_ne_bytes(t);
        d_chunk.copy_from_slice(&result.to_ne_bytes());
    }
    for (d, s) in d_chunks
        .into_remainder()
        .iter_mut()
        .zip(s_chunks.remainder())
    {
        *d ^= table[*s as usize];
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- Table sanity --

    #[test]
    fn exp_table_generates_all_nonzero() {
        let mut visited = [false; 256];
        for (i, &v) in EXP.iter().enumerate().take(255) {
            assert!(!visited[v as usize], "duplicate EXP[{i}] = {v}");
            visited[v as usize] = true;
        }
        // Zero should not appear in EXP[0..255]
        assert!(!visited[0], "zero should not be generated by EXP table");
    }

    #[test]
    fn log_exp_roundtrip() {
        for a in 1u16..=255 {
            let log_a = LOG[a as usize];
            assert_eq!(EXP[log_a as usize], a as u8, "roundtrip failed for {a}");
        }
    }

    #[test]
    fn exp_wraps_at_255() {
        // EXP[i] == EXP[i + 255] for i in 0..255
        for i in 0..255 {
            assert_eq!(EXP[i], EXP[i + 255], "mirror mismatch at {i}");
        }
    }

    // -- Field axioms --

    #[test]
    fn additive_identity() {
        for a in 0u8..=255 {
            let fa = Gf256(a);
            assert_eq!(fa + Gf256::ZERO, fa);
            assert_eq!(Gf256::ZERO + fa, fa);
        }
    }

    #[test]
    fn additive_inverse() {
        // In GF(2^n), every element is its own additive inverse.
        for a in 0u8..=255 {
            let fa = Gf256(a);
            assert_eq!(fa + fa, Gf256::ZERO);
        }
    }

    #[test]
    fn multiplicative_identity() {
        for a in 0u8..=255 {
            let fa = Gf256(a);
            assert_eq!(fa * Gf256::ONE, fa);
            assert_eq!(Gf256::ONE * fa, fa);
        }
    }

    #[test]
    fn multiplicative_inverse_all_nonzero() {
        for a in 1u8..=255 {
            let fa = Gf256(a);
            let inv = fa.inv();
            assert_eq!(
                fa * inv,
                Gf256::ONE,
                "a={a}, inv={}, product={}",
                inv.0,
                (fa * inv).0
            );
            assert_eq!(inv * fa, Gf256::ONE);
        }
    }

    #[test]
    #[should_panic(expected = "cannot invert zero")]
    fn inverse_of_zero_panics() {
        let _ = Gf256::ZERO.inv();
    }

    #[test]
    fn multiplication_commutative() {
        // Spot check: all pairs would be 65k, so test a representative sample.
        for a in (0u8..=255).step_by(7) {
            for b in (0u8..=255).step_by(11) {
                let fa = Gf256(a);
                let fb = Gf256(b);
                assert_eq!(fa * fb, fb * fa, "commutativity failed: {a} * {b}");
            }
        }
    }

    #[test]
    fn multiplication_associative() {
        let triples = [
            (3u8, 7, 11),
            (0, 100, 200),
            (1, 255, 128),
            (37, 42, 199),
            (255, 255, 255),
        ];
        for (a, b, c) in triples {
            let fa = Gf256(a);
            let fb = Gf256(b);
            let fc = Gf256(c);
            assert_eq!(
                (fa * fb) * fc,
                fa * (fb * fc),
                "associativity failed: {a} * {b} * {c}"
            );
        }
    }

    #[test]
    fn distributive_law() {
        let triples = [(3u8, 7, 11), (100, 200, 50), (255, 1, 0), (37, 42, 199)];
        for (a, b, c) in triples {
            let fa = Gf256(a);
            let fb = Gf256(b);
            let fc = Gf256(c);
            assert_eq!(
                fa * (fb + fc),
                fa * fb + fa * fc,
                "distributive law failed: {a} * ({b} + {c})"
            );
        }
    }

    #[test]
    fn zero_annihilates() {
        for a in 0u8..=255 {
            assert_eq!(Gf256(a) * Gf256::ZERO, Gf256::ZERO);
        }
    }

    // -- Exponentiation --

    #[test]
    fn pow_basic() {
        let g = Gf256::ALPHA; // generator = 2
        assert_eq!(g.pow(0), Gf256::ONE);
        assert_eq!(g.pow(1), g);
        // g^8 should equal the reduction of x^8 = x^4 + x^3 + x^2 + 1 = 0x1D = 29
        assert_eq!(g.pow(8), Gf256(POLY as u8));
    }

    #[test]
    fn pow_fermats_little() {
        // a^255 = 1 for all nonzero a in GF(256)
        for a in 1u8..=255 {
            assert_eq!(
                Gf256(a).pow(255),
                Gf256::ONE,
                "Fermat's little theorem failed for {a}"
            );
        }
    }

    // -- Division --

    #[test]
    fn division_is_mul_inverse() {
        let pairs = [(6u8, 3), (255, 1), (100, 200), (42, 37)];
        for (a, b) in pairs {
            let fa = Gf256(a);
            let fb = Gf256(b);
            assert_eq!(fa / fb, fa * fb.inv());
        }
    }

    #[test]
    fn div_self_is_one() {
        for a in 1u8..=255 {
            let fa = Gf256(a);
            assert_eq!(fa / fa, Gf256::ONE);
        }
    }

    // -- Bulk slice operations --

    #[test]
    fn add_slice_xors() {
        let mut dst = vec![0x00, 0xFF, 0xAA];
        let src = vec![0xFF, 0xFF, 0x55];
        gf256_add_slice(&mut dst, &src);
        assert_eq!(dst, vec![0xFF, 0x00, 0xFF]);
    }

    #[test]
    fn mul_slice_by_one_is_noop() {
        let original = vec![1, 2, 3, 100, 255];
        let mut data = original.clone();
        gf256_mul_slice(&mut data, Gf256::ONE);
        assert_eq!(data, original);
    }

    #[test]
    fn mul_slice_by_zero_clears() {
        let mut data = vec![1, 2, 3, 100, 255];
        gf256_mul_slice(&mut data, Gf256::ZERO);
        assert_eq!(data, vec![0, 0, 0, 0, 0]);
    }

    #[test]
    fn mul_slice_large_inputs() {
        // Exercise the `mul_with_table_wide` path (>= MUL_TABLE_THRESHOLD bytes).
        const LEN: usize = 64 + 7; // 71 bytes: crosses the 64-byte threshold
        let original: Vec<u8> = (0..LEN).map(|i| (i.wrapping_mul(37)) as u8).collect();
        let c = Gf256(13);
        let expected: Vec<u8> = original.iter().map(|&s| (Gf256(s) * c).0).collect();
        let mut data = original;
        gf256_mul_slice(&mut data, c);
        assert_eq!(data, expected);
    }

    #[test]
    fn addmul_slice_correctness() {
        let src = vec![1u8, 2, 3, 0, 255];
        let c = Gf256(7);
        let mut dst = vec![0u8; 5];
        gf256_addmul_slice(&mut dst, &src, c);
        // Verify element-wise
        for i in 0..5 {
            assert_eq!(dst[i], (Gf256(src[i]) * c).0);
        }
    }

    #[test]
    fn addmul_accumulates() {
        let src = vec![10u8, 20, 30];
        let c = Gf256(5);
        let mut dst = vec![1u8, 2, 3]; // nonzero initial
        let expected: Vec<u8> = dst
            .iter()
            .zip(src.iter())
            .map(|(&d, &s)| d ^ (Gf256(s) * c).0)
            .collect();
        gf256_addmul_slice(&mut dst, &src, c);
        assert_eq!(dst, expected);
    }

    #[test]
    fn addmul_slice_large_inputs() {
        const LEN: usize = 64 + 7;
        let src: Vec<u8> = (0..LEN).map(|i| (i.wrapping_mul(37)) as u8).collect();
        let c = Gf256(13);
        let mut dst = vec![0u8; LEN];
        let expected: Vec<u8> = src.iter().map(|&s| (Gf256(s) * c).0).collect();
        gf256_addmul_slice(&mut dst, &src, c);
        assert_eq!(dst, expected);
    }

    #[test]
    fn mul_slices2_matches_two_independent_mul_slice_calls() {
        const LEN_A: usize = 73;
        const LEN_B: usize = 131;
        let c1 = Gf256(29);
        let c2 = Gf256(113);

        let mut a_fused: Vec<u8> = (0..LEN_A).map(|i| (i.wrapping_mul(7)) as u8).collect();
        let mut b_fused: Vec<u8> = (0..LEN_B).map(|i| (i.wrapping_mul(11)) as u8).collect();
        let mut a_seq = a_fused.clone();
        let mut b_seq = b_fused.clone();

        gf256_mul_slices2(&mut a_fused, c1, &mut b_fused, c2);
        gf256_mul_slice(&mut a_seq, c1);
        gf256_mul_slice(&mut b_seq, c2);

        assert_eq!(a_fused, a_seq);
        assert_eq!(b_fused, b_seq);
    }

    #[test]
    fn addmul_slices2_matches_two_independent_addmul_slice_calls() {
        const LEN_A: usize = 79;
        const LEN_B: usize = 149;
        let c1 = Gf256(71);
        let c2 = Gf256(173);

        let src_a: Vec<u8> = (0..LEN_A).map(|i| (i.wrapping_mul(13)) as u8).collect();
        let src_b: Vec<u8> = (0..LEN_B).map(|i| (i.wrapping_mul(17)) as u8).collect();
        let mut accum_left: Vec<u8> = (0..LEN_A).map(|i| (i.wrapping_mul(19)) as u8).collect();
        let mut accum_right: Vec<u8> = (0..LEN_B).map(|i| (i.wrapping_mul(23)) as u8).collect();
        let mut expected_left = accum_left.clone();
        let mut expected_right = accum_right.clone();

        gf256_addmul_slices2(&mut accum_left, &src_a, c1, &mut accum_right, &src_b, c2);
        gf256_addmul_slice(&mut expected_left, &src_a, c1);
        gf256_addmul_slice(&mut expected_right, &src_b, c2);

        assert_eq!(accum_left, expected_left);
        assert_eq!(accum_right, expected_right);
    }

    #[test]
    fn add_slices2_matches_two_independent_add_slice_calls() {
        const LEN_A: usize = 83;
        const LEN_B: usize = 141;

        let src_a: Vec<u8> = (0..LEN_A).map(|i| (i.wrapping_mul(13)) as u8).collect();
        let src_b: Vec<u8> = (0..LEN_B).map(|i| (i.wrapping_mul(17)) as u8).collect();
        let mut accum_left: Vec<u8> = (0..LEN_A).map(|i| (i.wrapping_mul(19)) as u8).collect();
        let mut accum_right: Vec<u8> = (0..LEN_B).map(|i| (i.wrapping_mul(23)) as u8).collect();
        let mut expected_left = accum_left.clone();
        let mut expected_right = accum_right.clone();

        gf256_add_slices2(&mut accum_left, &src_a, &mut accum_right, &src_b);
        gf256_add_slice(&mut expected_left, &src_a);
        gf256_add_slice(&mut expected_right, &src_b);

        assert_eq!(accum_left, expected_left);
        assert_eq!(accum_right, expected_right);
    }

    #[test]
    fn simd_vs_scalar_mul_equivalence() {
        // Compare wide and scalar mul paths at various sizes.
        for &len in &[16usize, 17, 31, 64, 71, 128, 1024] {
            for &c_val in &[2u8, 13, 127, 255] {
                let c = Gf256(c_val);
                let original: Vec<u8> = (0..len)
                    .map(|i: usize| (i.wrapping_mul(37)) as u8)
                    .collect();
                let table = mul_table_for(c);

                let mut wide_dst = original.clone();
                let nib = NibbleTables::for_scalar(c);
                mul_with_table_wide(&mut wide_dst, &nib, table);

                let mut scalar_dst = original;
                mul_with_table_scalar(&mut scalar_dst, table);

                assert_eq!(wide_dst, scalar_dst, "mul mismatch: len={len}, c={c_val}");
            }
        }
    }

    #[test]
    fn simd_vs_scalar_addmul_equivalence() {
        // Compare wide and scalar addmul paths at various sizes.
        for &len in &[16usize, 17, 31, 64, 71, 128, 1024] {
            for &c_val in &[2u8, 13, 127, 255] {
                let c = Gf256(c_val);
                let src: Vec<u8> = (0..len)
                    .map(|i: usize| (i.wrapping_mul(37)) as u8)
                    .collect();
                let dst_init: Vec<u8> = (0..len)
                    .map(|i: usize| (i.wrapping_mul(53)) as u8)
                    .collect();
                let table = mul_table_for(c);

                let mut wide_dst = dst_init.clone();
                let nib = NibbleTables::for_scalar(c);
                addmul_with_table_wide(&mut wide_dst, &src, &nib, table);

                let mut scalar_dst = dst_init;
                addmul_with_table_scalar(&mut scalar_dst, &src, table);

                assert_eq!(
                    wide_dst, scalar_dst,
                    "addmul mismatch: len={len}, c={c_val}"
                );
            }
        }
    }

    #[test]
    fn dispatched_paths_match_scalar_reference() {
        const LEN: usize = 96;

        let src: Vec<u8> = (0..LEN).map(|i| (i.wrapping_mul(13)) as u8).collect();
        let original: Vec<u8> = (0..LEN).map(|i| (255u16 - i as u16) as u8).collect();
        let c = Gf256(29);

        let mut add_dispatch = original.clone();
        let mut add_scalar = original.clone();
        gf256_add_slice(&mut add_dispatch, &src);
        gf256_add_slice_scalar(&mut add_scalar, &src);
        assert_eq!(add_dispatch, add_scalar);

        let mut mul_dispatch = original.clone();
        let mut mul_scalar = original.clone();
        gf256_mul_slice(&mut mul_dispatch, c);
        gf256_mul_slice_scalar(&mut mul_scalar, c);
        assert_eq!(mul_dispatch, mul_scalar);

        let mut addmul_dispatch = original.clone();
        let mut addmul_scalar = original;
        gf256_addmul_slice(&mut addmul_dispatch, &src, c);
        gf256_addmul_slice_scalar(&mut addmul_scalar, &src, c);
        assert_eq!(addmul_dispatch, addmul_scalar);
    }

    // -- Pure data-type tests --

    #[test]
    fn gf256_debug_display_format() {
        let elem = Gf256(42);
        assert_eq!(format!("{elem:?}"), "GF(42)");
        assert_eq!(format!("{elem}"), "42");
        let zero = Gf256::ZERO;
        assert_eq!(format!("{zero:?}"), "GF(0)");
        assert_eq!(format!("{zero}"), "0");
    }

    #[test]
    fn gf256_default_is_zero() {
        let def = Gf256::default();
        assert_eq!(def, Gf256::ZERO);
        assert_eq!(def.0, 0);
    }

    #[test]
    fn gf256_clone_copy_eq_hash() {
        use std::collections::HashSet;
        let a = Gf256(100);
        let b = a; // Copy
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, Gf256(101));

        let mut set = HashSet::new();
        set.insert(Gf256(1));
        set.insert(Gf256(2));
        set.insert(Gf256(1)); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn sub_assign_works() {
        let mut a = Gf256(0xAB);
        a -= Gf256(0x55);
        // In GF(2^8), sub is the same as add (XOR).
        assert_eq!(a, Gf256(0xAB ^ 0x55));
    }

    #[test]
    fn mul_tables_consistent_with_element_mul() {
        // Verify that MUL_TABLES agrees with Gf256::mul_field for a sample.
        for c in (0u16..=255).step_by(17) {
            for x in (0u16..=255).step_by(13) {
                let expected = Gf256(c as u8).mul_field(Gf256(x as u8));
                assert_eq!(
                    MUL_TABLES[c as usize][x as usize], expected.0,
                    "MUL_TABLES[{c}][{x}] mismatch"
                );
            }
        }
    }
}
