//! Deterministic single-byte mutation appliers for connector response tests.

/// A deterministic mutation category used by [`crate::MutationHarness`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MutationKind {
    /// XOR one byte with one selected bit.
    BitFlip,
    /// Replace one byte with `0x00`.
    ByteZero,
    /// Replace one byte with `0xff`.
    ByteMax,
    /// Drop the tail from a selected offset.
    Truncate,
    /// Corrupt a recognized length-prefix byte.
    LengthPrefixCorrupt,
    /// Insert a `0x00` byte at a selected boundary.
    NullByteInjection,
    /// XOR one byte with `0x80`.
    HighBitFlip,
}

impl MutationKind {
    /// Stable ordered set used by the deterministic scheduler.
    pub const ALL: [Self; 7] = [
        Self::BitFlip,
        Self::ByteZero,
        Self::ByteMax,
        Self::Truncate,
        Self::LengthPrefixCorrupt,
        Self::NullByteInjection,
        Self::HighBitFlip,
    ];

    /// Deterministically pick a kind from a seed and mutation index.
    #[must_use]
    pub fn for_index(seed: u64, mutation_index: usize) -> Self {
        let schedule_len = u64::try_from(Self::ALL.len()).unwrap_or(1);
        let idx = seed
            .wrapping_add(u64::try_from(mutation_index).unwrap_or(u64::MAX))
            .wrapping_rem(schedule_len);
        Self::ALL
            .get(usize::try_from(idx).unwrap_or(0))
            .copied()
            .unwrap_or(Self::BitFlip)
    }

    const fn tag(self) -> u64 {
        match self {
            Self::BitFlip => 0,
            Self::ByteZero => 1,
            Self::ByteMax => 2,
            Self::Truncate => 3,
            Self::LengthPrefixCorrupt => 4,
            Self::NullByteInjection => 5,
            Self::HighBitFlip => 6,
        }
    }

    /// Apply this mutation to `input`.
    #[must_use]
    pub fn apply(self, input: &[u8], seed: u64, mutation_index: usize) -> Option<Mutant> {
        if input.is_empty() {
            return None;
        }

        let mut rng = DeterministicRng::new(seed, mutation_index, self);
        let position = rng.index(input.len());
        let mut bytes = input.to_vec();

        match self {
            Self::BitFlip => {
                bytes[position] ^= 1u8 << rng.index(8);
                Some(Mutant {
                    kind: self,
                    index: position,
                    bytes,
                })
            }
            Self::ByteZero => {
                bytes[position] = 0;
                Some(Mutant {
                    kind: self,
                    index: position,
                    bytes,
                })
            }
            Self::ByteMax => {
                bytes[position] = u8::MAX;
                Some(Mutant {
                    kind: self,
                    index: position,
                    bytes,
                })
            }
            Self::Truncate => {
                let truncate_at = truncate_index(input.len(), &mut rng);
                bytes.truncate(truncate_at);
                Some(Mutant {
                    kind: self,
                    index: truncate_at,
                    bytes,
                })
            }
            Self::LengthPrefixCorrupt => recognized_length_prefix(input).map(|prefix_index| {
                bytes[prefix_index] ^= 0x01;
                Mutant {
                    kind: self,
                    index: prefix_index,
                    bytes,
                }
            }),
            Self::NullByteInjection => {
                let insert_at = rng.index(input.len().saturating_add(1));
                bytes.insert(insert_at, 0);
                Some(Mutant {
                    kind: self,
                    index: insert_at,
                    bytes,
                })
            }
            Self::HighBitFlip => {
                bytes[position] ^= 0x80;
                Some(Mutant {
                    kind: self,
                    index: position,
                    bytes,
                })
            }
        }
    }
}

/// A mutated response plus enough metadata to reproduce it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mutant {
    pub kind: MutationKind,
    pub index: usize,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    fn new(seed: u64, mutation_index: usize, kind: MutationKind) -> Self {
        let kind_tag = kind.tag() + 0x9e37_79b9_7f4a_7c15;
        let state = seed
            ^ u64::try_from(mutation_index)
                .unwrap_or(u64::MAX)
                .rotate_left(17)
            ^ kind_tag.rotate_left(31);
        Self { state: state | 1 }
    }

    const fn next(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x | 1;
        self.state
    }

    fn index(&mut self, len: usize) -> usize {
        if len == 0 {
            return 0;
        }
        let len_u64 = u64::try_from(len).unwrap_or(u64::MAX);
        usize::try_from(self.next() % len_u64).unwrap_or(0)
    }
}

fn truncate_index(len: usize, rng: &mut DeterministicRng) -> usize {
    match rng.index(4) {
        0 => len.saturating_sub(1),
        1 => len.saturating_sub(16).max(1),
        2 => len.saturating_sub(64).max(1),
        _ => len / 2,
    }
}

fn recognized_length_prefix(input: &[u8]) -> Option<usize> {
    let payload_len = input.len().saturating_sub(1);
    if input
        .first()
        .is_some_and(|byte| usize::from(*byte) == payload_len)
    {
        return Some(0);
    }

    if input.len() >= 5 {
        let expected = u32::try_from(input.len().saturating_sub(4)).ok()?;
        let prefix = [input[0], input[1], input[2], input[3]];
        if u32::from_be_bytes(prefix) == expected || u32::from_le_bytes(prefix) == expected {
            return Some(3);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutation_kind_schedule_is_seed_deterministic() {
        let first: Vec<_> = (0..32).map(|idx| MutationKind::for_index(7, idx)).collect();
        let second: Vec<_> = (0..32).map(|idx| MutationKind::for_index(7, idx)).collect();

        assert_eq!(first, second);
    }

    #[test]
    fn bit_flip_is_reproducible() {
        let input = b"{\"ok\":true}";
        let first = MutationKind::BitFlip.apply(input, 42, 3).unwrap();
        let second = MutationKind::BitFlip.apply(input, 42, 3).unwrap();

        assert_eq!(first, second);
        assert_ne!(first.bytes, input);
    }

    #[test]
    fn length_prefix_corrupt_only_fires_on_recognized_prefix() {
        let mut input = vec![4, b't', b'e', b's', b't'];
        let mutant = MutationKind::LengthPrefixCorrupt
            .apply(&input, 0, 0)
            .expect("recognized one-byte prefix");
        assert_ne!(mutant.bytes[0], 4);

        input[0] = 9;
        assert!(
            MutationKind::LengthPrefixCorrupt
                .apply(&input, 0, 0)
                .is_none()
        );
    }
}
