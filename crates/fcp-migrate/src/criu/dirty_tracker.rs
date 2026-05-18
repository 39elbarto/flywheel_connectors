//! Dirty-page bitmap and soft-dirty capability detection.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use serde::{Deserialize, Serialize};
use thiserror::Error;

const PAGEMAP_ENTRY_BYTES: u64 = 8;
const PAGEMAP_ENTRY_BYTES_USIZE: usize = 8;
const PAGEMAP_SOFT_DIRTY_BIT: u8 = 55;
const PAGEMAP_PRESENT_BIT: u8 = 63;
const CLEAR_REFS_RESET_SOFT_DIRTY: &[u8] = b"4\n";

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoftDirtyPageState {
    pub page_idx: u64,
    pub pagemap_entry: u64,
    pub present: bool,
    pub soft_dirty: bool,
}

impl SoftDirtyPageState {
    #[must_use]
    pub const fn from_pagemap_entry(page_idx: u64, pagemap_entry: u64) -> Self {
        Self {
            page_idx,
            pagemap_entry,
            present: bit_is_set(pagemap_entry, PAGEMAP_PRESENT_BIT),
            soft_dirty: bit_is_set(pagemap_entry, PAGEMAP_SOFT_DIRTY_BIT),
        }
    }
}

pub trait SoftDirtyReader {
    /// Reads one virtual page's soft-dirty state.
    ///
    /// # Errors
    ///
    /// Returns [`DirtyTrackerError::SoftDirtyUnavailable`] when the backing
    /// reader cannot access or decode the page state.
    fn read_page_state(
        &self,
        virtual_page_idx: u64,
    ) -> Result<SoftDirtyPageState, DirtyTrackerError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoftDirtyProc {
    clear_refs_path: PathBuf,
    pagemap_path: PathBuf,
    page_size_bytes: u64,
}

impl SoftDirtyProc {
    #[must_use]
    pub fn for_self(page_size_bytes: u64) -> Self {
        Self::new(
            "/proc/self/clear_refs",
            "/proc/self/pagemap",
            page_size_bytes,
        )
    }

    #[must_use]
    pub fn new(
        clear_refs_path: impl Into<PathBuf>,
        pagemap_path: impl Into<PathBuf>,
        page_size_bytes: u64,
    ) -> Self {
        Self {
            clear_refs_path: clear_refs_path.into(),
            pagemap_path: pagemap_path.into(),
            page_size_bytes,
        }
    }

    #[must_use]
    pub const fn page_size_bytes(&self) -> u64 {
        self.page_size_bytes
    }

    #[must_use]
    pub fn clear_refs_path(&self) -> &Path {
        &self.clear_refs_path
    }

    #[must_use]
    pub fn pagemap_path(&self) -> &Path {
        &self.pagemap_path
    }

    /// Verifies that this procfs reader can attempt Linux soft-dirty tracking.
    ///
    /// # Errors
    ///
    /// Returns [`DirtyTrackerError::SoftDirtyUnavailable`] when the host is not
    /// Linux, the page size is zero, or required procfs files are missing.
    pub fn probe(&self) -> Result<(), DirtyTrackerError> {
        if !cfg!(target_os = "linux") {
            return Err(DirtyTrackerError::SoftDirtyUnavailable(
                "soft-dirty tracking requires Linux".to_owned(),
            ));
        }
        if self.page_size_bytes == 0 {
            return Err(DirtyTrackerError::SoftDirtyUnavailable(
                "page size must be greater than zero".to_owned(),
            ));
        }
        if !self.clear_refs_path.exists() {
            return Err(DirtyTrackerError::SoftDirtyUnavailable(format!(
                "clear_refs path is missing: {}",
                self.clear_refs_path.display()
            )));
        }
        if !self.pagemap_path.exists() {
            return Err(DirtyTrackerError::SoftDirtyUnavailable(format!(
                "pagemap path is missing: {}",
                self.pagemap_path.display()
            )));
        }
        Ok(())
    }

    /// Clears Linux soft-dirty bits for the current process via `clear_refs`.
    ///
    /// # Errors
    ///
    /// Returns [`DirtyTrackerError::SoftDirtyUnavailable`] when probing fails
    /// or the `clear_refs` file cannot be opened or written.
    pub fn reset_soft_dirty(&self) -> Result<(), DirtyTrackerError> {
        self.probe()?;
        let mut clear_refs = OpenOptions::new()
            .write(true)
            .open(&self.clear_refs_path)
            .map_err(|error| soft_dirty_io_error("open clear_refs for write", &error))?;
        clear_refs
            .write_all(CLEAR_REFS_RESET_SOFT_DIRTY)
            .map_err(|error| soft_dirty_io_error("write clear_refs soft-dirty reset", &error))
    }
}

impl SoftDirtyReader for SoftDirtyProc {
    fn read_page_state(
        &self,
        virtual_page_idx: u64,
    ) -> Result<SoftDirtyPageState, DirtyTrackerError> {
        self.probe()?;
        let mut pagemap = File::open(&self.pagemap_path)
            .map_err(|error| soft_dirty_io_error("open pagemap for read", &error))?;
        read_pagemap_page_state(&mut pagemap, virtual_page_idx)
    }
}

#[derive(Debug, Clone, Default)]
pub struct StaticSoftDirtyReader {
    states: BTreeMap<u64, SoftDirtyPageState>,
}

impl StaticSoftDirtyReader {
    #[must_use]
    pub fn from_dirty_pages(dirty_pages: impl IntoIterator<Item = u64>) -> Self {
        let states = dirty_pages
            .into_iter()
            .map(|page_idx| {
                (
                    page_idx,
                    SoftDirtyPageState::from_pagemap_entry(page_idx, soft_dirty_pagemap_entry()),
                )
            })
            .collect();
        Self { states }
    }
}

impl SoftDirtyReader for StaticSoftDirtyReader {
    fn read_page_state(
        &self,
        virtual_page_idx: u64,
    ) -> Result<SoftDirtyPageState, DirtyTrackerError> {
        Ok(self
            .states
            .get(&virtual_page_idx)
            .copied()
            .unwrap_or_else(|| {
                SoftDirtyPageState::from_pagemap_entry(virtual_page_idx, present_pagemap_entry())
            }))
    }
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

    /// Refreshes the bitmap from a soft-dirty reader.
    ///
    /// `first_virtual_page_idx` maps logical page `0` in this tracker to the
    /// virtual page index used by `/proc/self/pagemap`.
    ///
    /// # Errors
    ///
    /// Returns [`DirtyTrackerError::SoftDirtyUnavailable`] when the reader
    /// cannot read one of the tracked pages.
    pub fn refresh_from_soft_dirty_reader(
        &self,
        reader: &impl SoftDirtyReader,
        first_virtual_page_idx: u64,
    ) -> Result<u64, DirtyTrackerError> {
        let mut refreshed = 0_u64;
        for logical_page_idx in 0..self.page_count {
            let state =
                reader.read_page_state(first_virtual_page_idx.saturating_add(logical_page_idx))?;
            if state.soft_dirty {
                self.mark_page(logical_page_idx);
                refreshed = refreshed.saturating_add(1);
            }
        }
        Ok(refreshed)
    }

    /// Clears kernel soft-dirty state and this tracker's cached bitmap.
    ///
    /// # Errors
    ///
    /// Returns [`DirtyTrackerError::SoftDirtyUnavailable`] when the procfs
    /// soft-dirty reset fails.
    pub fn reset_soft_dirty_and_clear(
        &self,
        procfs: &SoftDirtyProc,
    ) -> Result<(), DirtyTrackerError> {
        procfs.reset_soft_dirty()?;
        self.clear();
        Ok(())
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
    SoftDirtyProc::for_self(4096).probe().is_ok()
}

#[must_use]
pub fn virtual_page_index(address: usize, page_size_bytes: u64) -> Option<u64> {
    if page_size_bytes == 0 {
        return None;
    }
    u64::try_from(address)
        .ok()
        .map(|addr| addr / page_size_bytes)
}

fn read_pagemap_page_state(
    pagemap: &mut (impl Read + Seek),
    virtual_page_idx: u64,
) -> Result<SoftDirtyPageState, DirtyTrackerError> {
    let offset = virtual_page_idx
        .checked_mul(PAGEMAP_ENTRY_BYTES)
        .ok_or_else(|| {
            DirtyTrackerError::SoftDirtyUnavailable(format!(
                "pagemap offset overflow for page {virtual_page_idx}"
            ))
        })?;
    pagemap
        .seek(SeekFrom::Start(offset))
        .map_err(|error| soft_dirty_io_error("seek pagemap entry", &error))?;
    let mut bytes = [0_u8; PAGEMAP_ENTRY_BYTES_USIZE];
    pagemap
        .read_exact(&mut bytes)
        .map_err(|error| soft_dirty_io_error("read pagemap entry", &error))?;
    Ok(SoftDirtyPageState::from_pagemap_entry(
        virtual_page_idx,
        u64::from_le_bytes(bytes),
    ))
}

const fn bit_is_set(value: u64, bit: u8) -> bool {
    value & (1_u64 << bit) != 0
}

const fn present_pagemap_entry() -> u64 {
    1_u64 << PAGEMAP_PRESENT_BIT
}

const fn soft_dirty_pagemap_entry() -> u64 {
    present_pagemap_entry() | (1_u64 << PAGEMAP_SOFT_DIRTY_BIT)
}

fn soft_dirty_io_error(context: &str, error: &std::io::Error) -> DirtyTrackerError {
    DirtyTrackerError::SoftDirtyUnavailable(format!("{context}: {error}"))
}
