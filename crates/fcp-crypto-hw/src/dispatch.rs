//! One-shot function table selection for cryptographic hot paths.

use std::sync::LazyLock;

use tracing::info;

use crate::cpuid::{HwFeatureSet, detect};

/// BLAKE3 hash dispatch function.
pub type Blake3Dispatch = fn(&[u8]) -> [u8; 32];

/// AES-GCM dispatch probe function.
///
/// This foundation bead does not implement production AES-GCM. The function
/// pointer shape exists so the downstream AES-GCM acceleration bead can swap in
/// a real encrypt/decrypt surface without changing table initialization.
pub type AesGcmDispatch = fn(&[u8]) -> [u8; 16];

/// NTT dispatch probe function for lattice/PQ hot paths.
pub type NttDispatch = fn(&[i32]) -> i64;

/// Selected dispatch tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchTier {
    /// Portable, always-safe implementation.
    Portable,
    /// x86 AES-NI/PCLMUL-capable tier.
    X86AesNi,
    /// x86 AVX2-capable tier.
    X86Avx2,
    /// x86 AVX-512 and VAES-capable tier.
    X86Avx512Vaes,
    /// `AArch64` crypto extension tier.
    Aarch64Crypto,
    /// `AArch64` SVE tier.
    Aarch64Sve,
}

impl DispatchTier {
    /// Stable string form for logs and JSON-adjacent diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Portable => "portable",
            Self::X86AesNi => "x86_aes_ni",
            Self::X86Avx2 => "x86_avx2",
            Self::X86Avx512Vaes => "x86_avx512_vaes",
            Self::Aarch64Crypto => "aarch64_crypto",
            Self::Aarch64Sve => "aarch64_sve",
        }
    }
}

/// Cryptographic dispatch table selected once per process.
#[derive(Clone, Copy)]
pub struct FunctionTable {
    /// Features used to select this table.
    pub features: HwFeatureSet,
    /// Selected implementation tier.
    pub tier: DispatchTier,
    /// BLAKE3 hash implementation.
    pub blake3: Blake3Dispatch,
    /// AES-GCM probe implementation.
    pub aes_gcm: AesGcmDispatch,
    /// Lattice NTT probe implementation.
    pub ntt: NttDispatch,
}

static FUNCTION_TABLE: LazyLock<FunctionTable> = LazyLock::new(|| build_function_table(detect()));

/// Return the process-wide crypto hardware function table.
#[must_use]
pub fn function_table() -> &'static FunctionTable {
    &FUNCTION_TABLE
}

/// Build a function table for an explicit feature set.
#[must_use]
pub fn build_function_table(features: HwFeatureSet) -> FunctionTable {
    let tier = select_tier(features);
    let features_detected = features.detected_feature_names();
    info!(
        target: "fcp_crypto_hw",
        dispatch_tier = tier.as_str(),
        ?features_detected,
        "crypto hardware dispatch table selected"
    );
    FunctionTable {
        features,
        tier,
        blake3: portable_blake3,
        aes_gcm: portable_aes_gcm_probe,
        ntt: portable_ntt_probe,
    }
}

const fn select_tier(features: HwFeatureSet) -> DispatchTier {
    if features.has_avx512_vaes {
        DispatchTier::X86Avx512Vaes
    } else if features.has_avx2 {
        DispatchTier::X86Avx2
    } else if features.has_aes_ni && features.has_clmul {
        DispatchTier::X86AesNi
    } else if features.has_aarch64_sve {
        DispatchTier::Aarch64Sve
    } else if features.has_aarch64_aes && features.has_aarch64_sha2 {
        DispatchTier::Aarch64Crypto
    } else {
        DispatchTier::Portable
    }
}

fn portable_blake3(input: &[u8]) -> [u8; 32] {
    *blake3::hash(input).as_bytes()
}

fn portable_aes_gcm_probe(input: &[u8]) -> [u8; 16] {
    let mut tagged = Vec::with_capacity(b"fcp-aes-gcm-dispatch-probe:".len() + input.len());
    tagged.extend_from_slice(b"fcp-aes-gcm-dispatch-probe:");
    tagged.extend_from_slice(input);
    let digest = blake3::hash(&tagged);
    let mut tag = [0_u8; 16];
    tag.copy_from_slice(&digest.as_bytes()[..16]);
    tag
}

fn portable_ntt_probe(input: &[i32]) -> i64 {
    input.iter().enumerate().fold(0_i64, |acc, (idx, value)| {
        let lane = i64::from(*value);
        let weight = i64::try_from(idx).unwrap_or(i64::MAX).saturating_add(1);
        acc.wrapping_add(lane.wrapping_mul(weight))
    })
}
