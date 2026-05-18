//! Dirty-page bitmap and soft-dirty capability detection.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DirtyTrackerError {
    #[error("soft-dirty tracking is unavailable: {0}")]
    SoftDirtyUnavailable(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DirtyTrackerMode {
    SoftDirty,
    PageWalkerFallback,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirtyTrackerHealth {
    pub kernel_supports_soft_dirty: bool,
    pub mode: DirtyTrackerMode,
    pub page_count: u64,
    pub page_size_bytes: u64,
    pub dirty_page_count: u64,
}

#[derive(Debug, Default, Clone)]
pub struct DirtyPageBitmap {
    dirty_pages: Arc<Mutex<BTreeSet<u64>>>,
}

impl DirtyPageBitmap {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mark(&self, page_idx: u64) {
        let mut dirty_pages = self.lock_dirty_pages();
        dirty_pages.insert(page_idx);
    }

    pub fn clear(&self) {
        let mut dirty_pages = self.lock_dirty_pages();
        dirty_pages.clear();
    }

    #[must_use]
    pub fn contains(&self, page_idx: u64) -> bool {
        let dirty_pages = self.lock_dirty_pages();
        dirty_pages.contains(&page_idx)
    }

    #[must_use]
    pub fn len(&self) -> u64 {
        let dirty_pages = self.lock_dirty_pages();
        u64::try_from(dirty_pages.len()).unwrap_or(u64::MAX)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[must_use]
    pub fn snapshot(&self) -> Vec<u64> {
        let dirty_pages = self.lock_dirty_pages();
        dirty_pages.iter().copied().collect()
    }

    fn lock_dirty_pages(&self) -> MutexGuard<'_, BTreeSet<u64>> {
        self.dirty_pages
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

#[derive(Debug, Clone)]
pub struct DirtyTracker {
    mode: DirtyTrackerMode,
    page_count: u64,
    page_size_bytes: u64,
    bitmap: DirtyPageBitmap,
}

impl DirtyTracker {
    #[must_use]
    pub fn new_auto(page_count: u64, page_size_bytes: u64) -> Self {
        let mode = if detect_soft_dirty_support() {
            DirtyTrackerMode::SoftDirty
        } else {
            DirtyTrackerMode::PageWalkerFallback
        };
        Self::with_mode(mode, page_count, page_size_bytes)
    }

    #[must_use]
    pub fn with_mode(mode: DirtyTrackerMode, page_count: u64, page_size_bytes: u64) -> Self {
        Self {
            mode,
            page_count,
            page_size_bytes,
            bitmap: DirtyPageBitmap::new(),
        }
    }

    #[must_use]
    pub fn from_soft_dirty_probe(
        page_count: u64,
        page_size_bytes: u64,
        probe_result: Result<(), DirtyTrackerError>,
    ) -> Self {
        match probe_result {
            Ok(()) => Self::with_mode(DirtyTrackerMode::SoftDirty, page_count, page_size_bytes),
            Err(error) => {
                tracing::warn!(
                    mode = "page_walker_fallback",
                    reason = %error,
                    "soft-dirty tracking unavailable; using page-walker fallback"
                );
                Self::with_mode(
                    DirtyTrackerMode::PageWalkerFallback,
                    page_count,
                    page_size_bytes,
                )
            }
        }
    }

    #[must_use]
    pub const fn mode(&self) -> DirtyTrackerMode {
        self.mode
    }

    #[must_use]
    pub const fn page_count(&self) -> u64 {
        self.page_count
    }

    #[must_use]
    pub const fn page_size_bytes(&self) -> u64 {
        self.page_size_bytes
    }

    pub fn clear(&self) {
        self.bitmap.clear();
    }

    pub fn mark_page(&self, page_idx: u64) {
        if page_idx < self.page_count {
            self.bitmap.mark(page_idx);
        }
    }

    pub fn record_write_range(&self, offset_bytes: u64, len_bytes: u64) {
        if self.page_size_bytes == 0 || len_bytes == 0 || self.page_count == 0 {
            return;
        }
        let start_page = offset_bytes / self.page_size_bytes;
        let end_byte = offset_bytes.saturating_add(len_bytes.saturating_sub(1));
        let end_page = end_byte / self.page_size_bytes;
        for page_idx in start_page..=end_page.min(self.page_count.saturating_sub(1)) {
            self.mark_page(page_idx);
        }
    }

    #[must_use]
    pub fn is_dirty(&self, page_idx: u64) -> bool {
        self.bitmap.contains(page_idx)
    }

    #[must_use]
    pub fn dirty_pages(&self) -> Vec<u64> {
        self.bitmap.snapshot()
    }

    #[must_use]
    pub fn dirty_page_count(&self) -> u64 {
        self.bitmap.len()
    }

    #[must_use]
    pub fn health(&self) -> DirtyTrackerHealth {
        DirtyTrackerHealth {
            kernel_supports_soft_dirty: self.mode == DirtyTrackerMode::SoftDirty,
            mode: self.mode,
            page_count: self.page_count,
            page_size_bytes: self.page_size_bytes,
            dirty_page_count: self.dirty_page_count(),
        }
    }
}

#[must_use]
pub fn detect_soft_dirty_support() -> bool {
    cfg!(target_os = "linux")
        && Path::new("/proc/self/clear_refs").exists()
        && Path::new("/proc/self/pagemap").exists()
}
