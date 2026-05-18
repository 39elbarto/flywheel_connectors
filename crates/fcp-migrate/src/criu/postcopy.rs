//! Post-copy page-fault forwarding decisions.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

pub const DEFAULT_PAGE_FAULT_TIMEOUT_MS: u64 = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageFetch {
    pub latency: Duration,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PostCopyFallbackDecision {
    FullReExecute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PostCopyDecision {
    Forwarded,
    Timeout,
    SourceMissing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PostCopyOutcome {
    Forwarded {
        page_addr: u64,
        source_peer: String,
        latency_us: u64,
        bytes_len: usize,
    },
    Timeout {
        page_addr: u64,
        source_peer: String,
        timeout_ms: u64,
        fallback: PostCopyFallbackDecision,
    },
    SourceMissing {
        page_addr: u64,
    },
}

impl PostCopyOutcome {
    #[must_use]
    pub const fn decision(&self) -> PostCopyDecision {
        match self {
            Self::Forwarded { .. } => PostCopyDecision::Forwarded,
            Self::Timeout { .. } => PostCopyDecision::Timeout,
            Self::SourceMissing { .. } => PostCopyDecision::SourceMissing,
        }
    }
}

pub trait PageFaultSource {
    #[must_use]
    fn fetch_page(&self, page_addr: u64, source_peer: &str) -> PageFetch;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostCopyForwarder {
    page_fault_timeout: Duration,
    sources_by_page: BTreeMap<u64, String>,
}

impl Default for PostCopyForwarder {
    fn default() -> Self {
        Self {
            page_fault_timeout: Duration::from_millis(DEFAULT_PAGE_FAULT_TIMEOUT_MS),
            sources_by_page: BTreeMap::new(),
        }
    }
}

impl PostCopyForwarder {
    #[must_use]
    pub const fn new(page_fault_timeout: Duration) -> Self {
        Self {
            page_fault_timeout,
            sources_by_page: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_source(mut self, page_addr: u64, source_peer: impl Into<String>) -> Self {
        self.sources_by_page.insert(page_addr, source_peer.into());
        self
    }

    #[must_use]
    pub const fn page_fault_timeout(&self) -> Duration {
        self.page_fault_timeout
    }

    #[must_use]
    pub fn resolve_fault(&self, page_addr: u64, source: &dyn PageFaultSource) -> PostCopyOutcome {
        let Some(source_peer) = self.sources_by_page.get(&page_addr) else {
            return PostCopyOutcome::SourceMissing { page_addr };
        };
        let fetch = source.fetch_page(page_addr, source_peer);
        if fetch.latency > self.page_fault_timeout {
            return PostCopyOutcome::Timeout {
                page_addr,
                source_peer: source_peer.clone(),
                timeout_ms: timeout_ms(self.page_fault_timeout),
                fallback: PostCopyFallbackDecision::FullReExecute,
            };
        }
        PostCopyOutcome::Forwarded {
            page_addr,
            source_peer: source_peer.clone(),
            latency_us: latency_us(fetch.latency),
            bytes_len: fetch.bytes.len(),
        }
    }
}

fn timeout_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn latency_us(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}
