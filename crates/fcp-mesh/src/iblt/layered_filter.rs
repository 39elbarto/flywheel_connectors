//! Layered Bloom + XOR filter for low-bandwidth anti-entropy hints.
//!
//! The Bloom layer is a cheap prefilter; the XOR layer is the compact
//! production membership hint. A lookup must pass both layers, so the observed
//! false-positive rate is bounded well below either layer alone while keeping
//! exact membership outside the security-critical revocation path.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use xorf::Filter as _;

/// Configuration for [`LayeredReconciliationFilter`].
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct LayeredFilterConfig {
    /// Target false-positive rate used by callers for acceptance checks.
    pub target_fpr: f64,
    /// Bloom filter bits allocated per inserted key.
    pub bloom_bits_per_key: u32,
    /// Number of Bloom hash probes.
    pub bloom_hashes: u8,
}

impl Default for LayeredFilterConfig {
    fn default() -> Self {
        Self {
            target_fpr: 1.0e-4,
            bloom_bits_per_key: 24,
            bloom_hashes: 8,
        }
    }
}

/// Immutable layered membership filter for gossip route selection.
#[derive(Debug, Clone)]
pub struct LayeredReconciliationFilter {
    config: LayeredFilterConfig,
    seed: u64,
    keys: BTreeSet<u64>,
    bloom_bits: Vec<u64>,
    bloom_bit_len: usize,
    xor: Option<xorf::Xor8>,
}

impl LayeredReconciliationFilter {
    /// Build a filter from raw item bytes.
    #[must_use]
    pub fn from_items<'a>(
        seed: u64,
        config: LayeredFilterConfig,
        items: impl IntoIterator<Item = &'a [u8]>,
    ) -> Self {
        let keys = items
            .into_iter()
            .map(|item| hash_item(seed, item))
            .collect::<BTreeSet<_>>();
        Self::from_keys(seed, config, keys)
    }

    /// Build a filter from pre-hashed keys.
    #[must_use]
    pub fn from_keys(seed: u64, config: LayeredFilterConfig, keys: BTreeSet<u64>) -> Self {
        let bloom_bit_len = bloom_bit_len(keys.len(), config.bloom_bits_per_key);
        let mut bloom_bits = vec![0_u64; bloom_bit_len.div_ceil(64)];
        for key in &keys {
            insert_bloom(
                &mut bloom_bits,
                bloom_bit_len,
                config.bloom_hashes,
                seed,
                *key,
            );
        }
        let xor = (!keys.is_empty()).then(|| {
            let key_vec = keys.iter().copied().collect::<Vec<_>>();
            xorf::Xor8::from(key_vec.as_slice())
        });

        Self {
            config,
            seed,
            keys,
            bloom_bits,
            bloom_bit_len,
            xor,
        }
    }

    /// Query whether an item may be present.
    #[must_use]
    pub fn may_contain(&self, item: &[u8]) -> bool {
        self.may_contain_key(hash_item(self.seed, item))
    }

    /// Query whether a pre-hashed key may be present.
    #[must_use]
    pub fn may_contain_key(&self, key: u64) -> bool {
        if self.keys.contains(&key) {
            return true;
        }
        if self.keys.is_empty()
            || !bloom_contains(
                &self.bloom_bits,
                self.bloom_bit_len,
                self.config.bloom_hashes,
                self.seed,
                key,
            )
        {
            return false;
        }
        self.xor
            .as_ref()
            .is_some_and(|xor_filter| xor_filter.contains(&key))
    }

    /// Number of distinct keys in the filter.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the filter has no keys.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Configured target false-positive rate.
    #[must_use]
    pub const fn target_fpr(&self) -> f64 {
        self.config.target_fpr
    }
}

fn bloom_bit_len(key_count: usize, bits_per_key: u32) -> usize {
    let bits_per_key = usize::try_from(bits_per_key).unwrap_or(usize::MAX).max(1);
    key_count
        .max(1)
        .saturating_mul(bits_per_key)
        .max(64)
        .div_ceil(64)
        .saturating_mul(64)
}

fn hash_item(seed: u64, item: &[u8]) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"FCP-MESH-LAYERED-FILTER-V1");
    hasher.update(&seed.to_le_bytes());
    hasher.update(item);
    let hash = hasher.finalize();
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&hash.as_bytes()[..8]);
    u64::from_le_bytes(bytes)
}

fn hash_probe(seed: u64, key: u64, probe: u8, bit_len: usize) -> usize {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"FCP-MESH-LAYERED-BLOOM-PROBE-V1");
    hasher.update(&seed.to_le_bytes());
    hasher.update(&key.to_le_bytes());
    hasher.update(&[probe]);
    let hash = hasher.finalize();
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&hash.as_bytes()[..8]);
    let value = u64::from_le_bytes(bytes);
    let bit_len = u64::try_from(bit_len).expect("bloom bit length fits u64");
    usize::try_from(value % bit_len).expect("modulo result fits usize")
}

fn insert_bloom(bits: &mut [u64], bit_len: usize, probes: u8, seed: u64, key: u64) {
    for probe in 0..probes.max(1) {
        let index = hash_probe(seed, key, probe, bit_len);
        bits[index / 64] |= 1_u64 << (index % 64);
    }
}

fn bloom_contains(bits: &[u64], bit_len: usize, probes: u8, seed: u64, key: u64) -> bool {
    (0..probes.max(1)).all(|probe| {
        let index = hash_probe(seed, key, probe, bit_len);
        (bits[index / 64] & (1_u64 << (index % 64))) != 0
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(label: &str) -> Vec<u8> {
        label.as_bytes().to_vec()
    }

    #[test]
    fn layered_filter_has_no_false_negatives() {
        let items = (0..1_000)
            .map(|index| item(&format!("object-{index:04}")))
            .collect::<Vec<_>>();
        let filter = LayeredReconciliationFilter::from_items(
            7,
            LayeredFilterConfig::default(),
            items.iter().map(Vec::as_slice),
        );

        for item in &items {
            assert!(filter.may_contain(item));
        }
    }

    #[test]
    fn layered_filter_fpr_budget_enforced() {
        let items = (0..1_000)
            .map(|index| item(&format!("member-{index:04}")))
            .collect::<Vec<_>>();
        let filter = LayeredReconciliationFilter::from_items(
            11,
            LayeredFilterConfig::default(),
            items.iter().map(Vec::as_slice),
        );

        let false_positives = (0..10_000)
            .filter(|index| filter.may_contain(format!("non-member-{index:04}").as_bytes()))
            .count();
        let numerator = f64::from(u32::try_from(false_positives).expect("query count fits u32"));
        let observed = numerator / 10_000.0;

        assert!(
            observed < filter.target_fpr(),
            "observed false-positive rate {observed} exceeded {}",
            filter.target_fpr()
        );
    }

    #[test]
    fn empty_layered_filter_rejects_queries() {
        let filter = LayeredReconciliationFilter::from_items(
            0,
            LayeredFilterConfig::default(),
            std::iter::empty(),
        );

        assert!(filter.is_empty());
        assert!(!filter.may_contain(b"anything"));
    }
}
