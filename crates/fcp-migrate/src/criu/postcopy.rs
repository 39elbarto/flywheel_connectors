//! Post-copy page-fault forwarding decisions.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

pub const DEFAULT_PAGE_FAULT_TIMEOUT_MS: u64 = 100;
pub const POSTCOPY_PAGE_FAULT_OTLP_SPAN: &str = "fcp.criu.postcopy_fault";

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostCopyFaultTrace {
    pub page_addr: u64,
    pub source_peer: Option<String>,
    pub latency_us: Option<u64>,
    pub timeout_ms: Option<u64>,
    pub decision: PostCopyDecision,
    pub fallback: Option<PostCopyFallbackDecision>,
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

    #[must_use]
    pub fn trace_event(&self) -> PostCopyFaultTrace {
        match self {
            Self::Forwarded {
                page_addr,
                source_peer,
                latency_us,
                ..
            } => PostCopyFaultTrace {
                page_addr: *page_addr,
                source_peer: Some(source_peer.clone()),
                latency_us: Some(*latency_us),
                timeout_ms: None,
                decision: PostCopyDecision::Forwarded,
                fallback: None,
            },
            Self::Timeout {
                page_addr,
                source_peer,
                timeout_ms,
                fallback,
            } => PostCopyFaultTrace {
                page_addr: *page_addr,
                source_peer: Some(source_peer.clone()),
                latency_us: None,
                timeout_ms: Some(*timeout_ms),
                decision: PostCopyDecision::Timeout,
                fallback: Some(*fallback),
            },
            Self::SourceMissing { page_addr } => PostCopyFaultTrace {
                page_addr: *page_addr,
                source_peer: None,
                latency_us: None,
                timeout_ms: None,
                decision: PostCopyDecision::SourceMissing,
                fallback: None,
            },
        }
    }

    #[must_use]
    pub fn otlp_span(&self) -> tracing::Span {
        let trace = self.trace_event();
        tracing::trace_span!(
            POSTCOPY_PAGE_FAULT_OTLP_SPAN,
            page_addr = trace.page_addr,
            source_peer = trace.source_peer.as_deref().unwrap_or(""),
            latency_us = trace.latency_us.unwrap_or(0),
            timeout_ms = trace.timeout_ms.unwrap_or(0),
            decision = ?trace.decision,
            fallback = ?trace.fallback,
        )
    }

    pub fn emit_trace(&self) {
        let trace = self.trace_event();
        tracing::trace!(
            target: "fcp.criu",
            page_addr = trace.page_addr,
            source_peer = trace.source_peer.as_deref().unwrap_or(""),
            latency_us = trace.latency_us.unwrap_or(0),
            timeout_ms = trace.timeout_ms.unwrap_or(0),
            decision = ?trace.decision,
            fallback = ?trace.fallback,
            "CRIU post-copy page fault"
        );
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
            return record_fault_outcome(PostCopyOutcome::SourceMissing { page_addr });
        };
        let fetch = source.fetch_page(page_addr, source_peer);
        if fetch.latency > self.page_fault_timeout {
            return record_fault_outcome(PostCopyOutcome::Timeout {
                page_addr,
                source_peer: source_peer.clone(),
                timeout_ms: timeout_ms(self.page_fault_timeout),
                fallback: PostCopyFallbackDecision::FullReExecute,
            });
        }
        record_fault_outcome(PostCopyOutcome::Forwarded {
            page_addr,
            source_peer: source_peer.clone(),
            latency_us: latency_us(fetch.latency),
            bytes_len: fetch.bytes.len(),
        })
    }
}

fn record_fault_outcome(outcome: PostCopyOutcome) -> PostCopyOutcome {
    outcome.emit_trace();
    outcome
}

fn timeout_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn latency_us(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}
