//! Masked IBLT wrapper for mesh anti-entropy.
//!
//! The underlying IBLT still peels over `ObjectId`-sized keys, but each key is
//! XOR-masked before it is inserted into the sketch. Peers that reconcile the
//! same zone use the same mask, so subtraction/peeling is unchanged while the
//! wire sketch no longer contains raw object-id XOR sums.

use fcp_prelude::{ObjectId, ZoneId};
use serde::{Deserialize, Serialize};

use super::{Iblt, IbltDecodeResult, IbltError};

/// Stable 32-byte mask used before inserting object IDs into an IBLT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct IbltMask([u8; 32]);

impl IbltMask {
    /// Create a mask from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Derive the deterministic mask used for one mesh zone.
    #[must_use]
    pub fn for_zone(zone_id: &ZoneId) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"FCP-MESH-MASKED-IBLT-ZONE-V1");
        hasher.update(zone_id.as_bytes());
        Self(*hasher.finalize().as_bytes())
    }

    /// Raw mask bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Apply or remove the mask. XOR is its own inverse.
    #[must_use]
    pub fn apply(self, object_id: ObjectId) -> ObjectId {
        let mut masked = *object_id.as_bytes();
        for (byte, mask_byte) in masked.iter_mut().zip(self.0) {
            *byte ^= mask_byte;
        }
        ObjectId::from_bytes(masked)
    }
}

/// Errors returned by masked IBLT operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MaskedIbltError {
    /// The underlying sketches use different cell counts.
    #[error(transparent)]
    Iblt(#[from] IbltError),
    /// Sketches must use the same object-id mask before subtraction.
    #[error("masked iblt mask mismatch")]
    MaskMismatch,
    /// The sketch could not be fully peeled within its cell budget.
    #[error("masked iblt decode incomplete: {remaining_nonzero_cells} non-zero cells remain")]
    DecodeIncomplete {
        /// Non-zero cells still present after peeling stalled.
        remaining_nonzero_cells: usize,
    },
}

/// IBLT whose object IDs are masked before insertion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaskedIblt {
    mask: IbltMask,
    iblt: Iblt,
}

impl MaskedIblt {
    /// Build a masked IBLT sized for an expected difference set.
    #[must_use]
    pub fn with_expected_difference(mask: IbltMask, expected_difference: usize) -> Self {
        Self {
            mask,
            iblt: Iblt::with_expected_difference(expected_difference),
        }
    }

    /// Build a masked IBLT with an explicit cell count.
    ///
    /// # Errors
    ///
    /// Returns [`IbltError::InvalidCellCount`] when `cell_count` is too small.
    pub fn with_cell_count(mask: IbltMask, cell_count: usize) -> Result<Self, IbltError> {
        Ok(Self {
            mask,
            iblt: Iblt::with_cell_count(cell_count)?,
        })
    }

    /// Mask used by this sketch.
    #[must_use]
    pub const fn mask(&self) -> IbltMask {
        self.mask
    }

    /// Number of cells in the underlying sketch.
    #[must_use]
    pub fn cell_count(&self) -> usize {
        self.iblt.cell_count()
    }

    /// Borrow the masked-key IBLT.
    #[must_use]
    pub const fn as_iblt(&self) -> &Iblt {
        &self.iblt
    }

    /// Insert an object ID after masking it.
    pub fn insert(&mut self, object_id: ObjectId) {
        self.iblt.insert(self.mask.apply(object_id));
    }

    /// Delete an object ID after masking it.
    pub fn delete(&mut self, object_id: ObjectId) {
        self.iblt.delete(self.mask.apply(object_id));
    }

    /// Subtract another masked sketch from this one.
    ///
    /// # Errors
    ///
    /// Returns [`MaskedIbltError::MaskMismatch`] when sketches do not share a
    /// mask, or an IBLT error when cell counts differ.
    pub fn subtract(&self, other: &Self) -> Result<Self, MaskedIbltError> {
        if self.mask != other.mask {
            return Err(MaskedIbltError::MaskMismatch);
        }
        Ok(Self {
            mask: self.mask,
            iblt: self.iblt.subtract(&other.iblt)?,
        })
    }

    /// Decode and unmask the difference result.
    pub fn decode(&self) -> IbltDecodeResult {
        unmask_decode_result(self.iblt.decode(), self.mask)
    }

    /// Decode and require a complete peel.
    ///
    /// # Errors
    ///
    /// Returns [`MaskedIbltError::DecodeIncomplete`] when the sketch is
    /// overloaded and callers must fall back to a bounded list exchange.
    pub fn decode_complete(&self) -> Result<IbltDecodeResult, MaskedIbltError> {
        let result = self.decode();
        if result.complete {
            Ok(result)
        } else {
            Err(MaskedIbltError::DecodeIncomplete {
                remaining_nonzero_cells: result.remaining_nonzero_cells,
            })
        }
    }
}

pub(crate) fn unmask_decode_result(result: IbltDecodeResult, mask: IbltMask) -> IbltDecodeResult {
    IbltDecodeResult {
        only_left: result
            .only_left
            .into_iter()
            .map(|object_id| mask.apply(object_id))
            .collect(),
        only_right: result
            .only_right
            .into_iter()
            .map(|object_id| mask.apply(object_id))
            .collect(),
        complete: result.complete,
        remaining_nonzero_cells: result.remaining_nonzero_cells,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn object_id(label: &str) -> ObjectId {
        ObjectId::from_unscoped_bytes(label.as_bytes())
    }

    #[test]
    fn masked_iblt_decodes_symmetric_diff() {
        let zone = ZoneId::work();
        let mask = IbltMask::for_zone(&zone);
        let mut left = MaskedIblt::with_expected_difference(mask, 8);
        let mut right = MaskedIblt::with_expected_difference(mask, 8);

        for index in 0..1_000 {
            let object_id = object_id(&format!("shared-{index:04}"));
            left.insert(object_id);
            right.insert(object_id);
        }

        let left_only = object_id("left-only-a");
        let right_only_a = object_id("right-only-a");
        let right_only_b = object_id("right-only-b");
        left.insert(left_only);
        right.insert(right_only_a);
        right.insert(right_only_b);

        let decoded = left
            .subtract(&right)
            .expect("same mask and cell count")
            .decode();

        assert!(decoded.is_complete());
        assert!(decoded.only_left.contains(&left_only));
        assert!(decoded.only_right.contains(&right_only_a));
        assert!(decoded.only_right.contains(&right_only_b));
        assert_eq!(decoded.only_left.len(), 1);
        assert_eq!(decoded.only_right.len(), 2);
    }

    #[test]
    fn masked_iblt_rejects_mask_mismatch() {
        let left = MaskedIblt::with_expected_difference(IbltMask::from_bytes([1; 32]), 4);
        let right = MaskedIblt::with_expected_difference(IbltMask::from_bytes([2; 32]), 4);

        assert_eq!(
            left.subtract(&right).expect_err("mismatched masks fail"),
            MaskedIbltError::MaskMismatch
        );
    }

    #[test]
    fn mask_round_trip_is_reversible() {
        let mask = IbltMask::from_bytes([0xA5; 32]);
        let object_id = object_id("round-trip");
        assert_ne!(mask.apply(object_id), object_id);
        assert_eq!(mask.apply(mask.apply(object_id)), object_id);
    }

    #[test]
    fn masked_iblt_reports_overload_for_fallback() {
        let mask = IbltMask::for_zone(&ZoneId::work());
        let mut left = MaskedIblt::with_expected_difference(mask, 4);
        let right = MaskedIblt::with_expected_difference(mask, 4);

        for index in 0..200 {
            left.insert(object_id(&format!("left-heavy-{index:04}")));
        }

        let err = left
            .subtract(&right)
            .expect("same mask and cell count")
            .decode_complete()
            .expect_err("overloaded sketch should require fallback");

        assert!(matches!(
            err,
            MaskedIbltError::DecodeIncomplete {
                remaining_nonzero_cells
            } if remaining_nonzero_cells > 0
        ));
    }

    #[test]
    fn masked_iblt_decodes_small_diff_under_latency_budget() {
        let mask = IbltMask::for_zone(&ZoneId::work());
        let mut left = MaskedIblt::with_expected_difference(mask, 20);
        let mut right = MaskedIblt::with_expected_difference(mask, 20);

        for index in 0..1_000 {
            let shared = object_id(&format!("latency-shared-{index:04}"));
            left.insert(shared);
            right.insert(shared);
        }
        for index in 0..20 {
            left.insert(object_id(&format!("latency-left-{index:04}")));
        }

        let diff = left.subtract(&right).expect("same mask and cell count");
        let start = Instant::now();
        let decoded = diff.decode_complete().expect("diff should fit budget");
        let elapsed = start.elapsed();

        assert_eq!(decoded.only_left.len(), 20);
        assert!(decoded.only_right.is_empty());
        assert!(
            elapsed.as_millis() < 8,
            "masked IBLT decode took {elapsed:?}, expected <8ms for diff<=20"
        );
    }
}
