use fcp_migrate::{DirtyTracker, DirtyTrackerMode};
use proptest::prelude::*;

const PAGE_COUNT: u64 = 128;
const PAGE_SIZE_BYTES: u64 = 4096;

#[test]
fn clear_then_dirty_then_read_returns_dirty() {
    let tracker = tracker();
    tracker.clear();

    tracker.record_write_range(PAGE_SIZE_BYTES * 7, 1);

    assert!(tracker.is_dirty(7));
    assert_eq!(tracker.dirty_page_count(), 1);
}

#[test]
fn clear_after_read_returns_clean() {
    let tracker = tracker();
    tracker.record_write_range(PAGE_SIZE_BYTES * 3, PAGE_SIZE_BYTES);
    assert!(tracker.is_dirty(3));

    tracker.clear();

    assert!(!tracker.is_dirty(3));
    assert_eq!(tracker.dirty_page_count(), 0);
}

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: None,
        .. ProptestConfig::default()
    })]

    #[test]
    fn write_range_marks_every_touched_page(start_page in 0_u64..PAGE_COUNT, page_span in 1_u64..8) {
        let tracker = tracker();
        let len_bytes = page_span.saturating_mul(PAGE_SIZE_BYTES);

        tracker.record_write_range(start_page.saturating_mul(PAGE_SIZE_BYTES), len_bytes);

        let end_page = start_page
            .saturating_add(page_span)
            .saturating_sub(1)
            .min(PAGE_COUNT.saturating_sub(1));
        for page_idx in start_page..=end_page {
            prop_assert!(tracker.is_dirty(page_idx), "page {page_idx} should be dirty");
        }
    }
}

#[test]
fn health_reports_fallback_mode_and_counts() {
    let tracker = tracker();
    tracker.record_write_range(0, PAGE_SIZE_BYTES * 2);

    let health = tracker.health();

    assert!(!health.kernel_supports_soft_dirty);
    assert_eq!(health.mode, DirtyTrackerMode::PageWalkerFallback);
    assert_eq!(health.dirty_page_count, 2);
}

fn tracker() -> DirtyTracker {
    DirtyTracker::with_mode(
        DirtyTrackerMode::PageWalkerFallback,
        PAGE_COUNT,
        PAGE_SIZE_BYTES,
    )
}
