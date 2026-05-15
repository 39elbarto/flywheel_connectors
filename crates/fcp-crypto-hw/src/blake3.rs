//! BLAKE3 dispatch helpers.
//!
//! The upstream `blake3` crate owns the low-level SIMD implementation and
//! runtime CPU dispatch. This module keeps the FCP-facing tier selection,
//! operator override, and byte-equivalence contract explicit so future
//! acceleration work can replace an individual tier without changing callers.

use std::{env, error::Error, fmt};

use serde::{Deserialize, Serialize};

use crate::cpuid::HwFeatureSet;

/// BLAKE3 implementation tier selected by FCP dispatch policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Blake3Tier {
    /// Portable reference path.
    Portable,
    /// x86 AVX2-capable path.
    X86Avx2,
    /// x86 AVX-512-capable path.
    X86Avx512,
    /// `AArch64` NEON-capable path.
    Neon,
}

impl Blake3Tier {
    /// Stable string form for logs, docs, and JSON evidence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Portable => "portable",
            Self::X86Avx2 => "x86_avx2",
            Self::X86Avx512 => "x86_avx512",
            Self::Neon => "neon",
        }
    }

    /// Parse a stable tier name.
    ///
    /// # Errors
    ///
    /// Returns [`Blake3DispatchError::UnknownTier`] when `value` is not one of
    /// the stable operator-facing tier names.
    pub fn parse(value: &str) -> Result<Self, Blake3DispatchError> {
        match value {
            "portable" => Ok(Self::Portable),
            "x86_avx2" | "avx2" => Ok(Self::X86Avx2),
            "x86_avx512" | "avx512" | "avx512f" => Ok(Self::X86Avx512),
            "neon" | "aarch64_neon" => Ok(Self::Neon),
            other => Err(Blake3DispatchError::UnknownTier {
                value: other.to_owned(),
            }),
        }
    }
}

/// Error returned while selecting a BLAKE3 dispatch tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Blake3DispatchError {
    /// The requested override was not a known stable tier name.
    UnknownTier {
        /// Raw operator-provided tier name.
        value: String,
    },
    /// `FCP_FORCE_BLAKE3_TIER` was present but not valid Unicode.
    InvalidOverrideUnicode,
}

impl fmt::Display for Blake3DispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTier { value } => {
                write!(f, "unknown BLAKE3 dispatch tier override: {value}")
            }
            Self::InvalidOverrideUnicode => {
                f.write_str("FCP_FORCE_BLAKE3_TIER is not valid Unicode")
            }
        }
    }
}

impl Error for Blake3DispatchError {}

/// FCP-facing BLAKE3 hasher with an explicit selected tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Blake3Hasher {
    tier: Blake3Tier,
}

impl Blake3Hasher {
    /// Create a hasher from detected hardware features.
    #[must_use]
    pub const fn from_features(features: HwFeatureSet) -> Self {
        Self {
            tier: select_blake3_tier(features),
        }
    }

    /// Create a hasher from detected features and an optional operator override.
    ///
    /// # Errors
    ///
    /// Returns [`Blake3DispatchError::UnknownTier`] when `override_value`
    /// contains an unsupported tier name.
    pub fn from_features_with_override(
        features: HwFeatureSet,
        override_value: Option<&str>,
    ) -> Result<Self, Blake3DispatchError> {
        let tier = match override_value {
            Some(value) if !value.trim().is_empty() => Blake3Tier::parse(value.trim())?,
            _ => select_blake3_tier(features),
        };
        Ok(Self { tier })
    }

    /// Create a hasher from detected features and `FCP_FORCE_BLAKE3_TIER`.
    ///
    /// # Errors
    ///
    /// Returns [`Blake3DispatchError::UnknownTier`] when the environment value
    /// names an unsupported tier. Returns
    /// [`Blake3DispatchError::InvalidOverrideUnicode`] when the environment
    /// variable is present but not valid Unicode.
    pub fn from_env(features: HwFeatureSet) -> Result<Self, Blake3DispatchError> {
        match env::var("FCP_FORCE_BLAKE3_TIER") {
            Ok(value) => Self::from_features_with_override(features, Some(&value)),
            Err(env::VarError::NotPresent) => Ok(Self::from_features(features)),
            Err(env::VarError::NotUnicode(_)) => Err(Blake3DispatchError::InvalidOverrideUnicode),
        }
    }

    /// Create a hasher for an explicit tier.
    #[must_use]
    pub const fn with_tier(tier: Blake3Tier) -> Self {
        Self { tier }
    }

    /// Return the selected dispatch tier.
    #[must_use]
    pub const fn tier(self) -> Blake3Tier {
        self.tier
    }

    /// Hash bytes through the selected BLAKE3 tier.
    #[must_use]
    pub fn hash(self, input: &[u8]) -> [u8; 32] {
        match self.tier {
            Blake3Tier::Portable => hash_portable(input),
            Blake3Tier::X86Avx2 => hash_x86_avx2(input),
            Blake3Tier::X86Avx512 => hash_x86_avx512(input),
            Blake3Tier::Neon => hash_neon(input),
        }
    }

    /// Return every BLAKE3 tier that is safe to exercise for a feature set.
    #[must_use]
    pub fn available_tiers(features: HwFeatureSet) -> Vec<Blake3Tier> {
        let mut tiers = vec![Blake3Tier::Portable];
        if features.has_avx2 {
            tiers.push(Blake3Tier::X86Avx2);
        }
        if features.has_avx512f {
            tiers.push(Blake3Tier::X86Avx512);
        }
        if features.has_aarch64_aes || features.has_aarch64_sha2 || features.has_aarch64_sve {
            tiers.push(Blake3Tier::Neon);
        }
        tiers
    }
}

/// Hash bytes with the runtime-selected BLAKE3 dispatch path.
#[must_use]
pub fn hash_auto(input: &[u8]) -> [u8; 32] {
    hash_with_upstream_runtime(input)
}

/// Hash bytes with the portable BLAKE3 tier.
#[must_use]
pub fn hash_portable(input: &[u8]) -> [u8; 32] {
    hash_with_upstream_runtime(input)
}

/// Hash bytes with the x86 AVX2 BLAKE3 tier.
#[must_use]
pub fn hash_x86_avx2(input: &[u8]) -> [u8; 32] {
    hash_with_upstream_runtime(input)
}

/// Hash bytes with the x86 AVX-512 BLAKE3 tier.
#[must_use]
pub fn hash_x86_avx512(input: &[u8]) -> [u8; 32] {
    hash_with_upstream_runtime(input)
}

/// Hash bytes with the `AArch64` NEON BLAKE3 tier.
#[must_use]
pub fn hash_neon(input: &[u8]) -> [u8; 32] {
    hash_with_upstream_runtime(input)
}

const fn select_blake3_tier(features: HwFeatureSet) -> Blake3Tier {
    if features.has_avx512f {
        Blake3Tier::X86Avx512
    } else if features.has_avx2 {
        Blake3Tier::X86Avx2
    } else if features.has_aarch64_sve || features.has_aarch64_aes || features.has_aarch64_sha2 {
        Blake3Tier::Neon
    } else {
        Blake3Tier::Portable
    }
}

fn hash_with_upstream_runtime(input: &[u8]) -> [u8; 32] {
    *::blake3::hash(input).as_bytes()
}
