//! Mesh-aware live-truth resolver and provenance taxonomy.
//!
//! Provides a unified resolution model that classifies runtime knowledge
//! into explicit [`KnowledgeState`]s — offline, node-local, mesh-backed,
//! degraded, or fallback-derived — and wraps every answer with
//! [`TruthFreshness`] and a [`DecisionTrace`] so downstream consumers
//! and audit surfaces can understand *why* a particular answer was
//! produced and how much to trust it.
//!
//! # Architecture
//!
//! The [`LiveTruthResolver`] queries truth sources in precedence order
//! determined by a [`ResolutionStrategy`]:
//!
//! ```text
//! BestAvailable (default):
//!   1. MeshBacked   — distributed state from the mesh object store
//!   2. HostBacked   — live host admin API (node-local authoritative)
//!   3. NodeLocal    — cached/persisted local state
//!   4. Offline      — static artifacts (manifests, registry cache)
//!
//! PreferHost:
//!   1. HostBacked   — live host API first
//!   2. MeshBacked   — mesh fallback
//!   3. NodeLocal / Offline
//!
//! OfflineOnly:
//!   Only offline artifacts, no network queries
//! ```
//!
//! Every resolution attempt records which sources were tried, which
//! succeeded or failed, and which source was ultimately selected — this
//! is the [`DecisionTrace`]. The trace is machine-readable so acceptance
//! tests can assert resolver ordering and fallback semantics.

use std::fmt;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::catalog::CommandTruthSource;
use crate::intent::IntentProvenance;

// ─────────────────────────────────────────────────────────────────────────────
// Knowledge State Taxonomy
// ─────────────────────────────────────────────────────────────────────────────

/// Classification of where a resolved truth answer originates.
///
/// This is the provenance taxonomy for kpj16.1: every answer the CLI
/// produces carries one of these states so operators and automation can
/// distinguish live distributed truth from cached local artifacts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KnowledgeState {
    /// Answer derived from mesh-backed distributed state.
    ///
    /// The mesh object store was queried and returned a durable,
    /// replicated answer. This is the highest-confidence source for
    /// runtime state that has been committed to the mesh.
    MeshBacked,

    /// Answer from the live host admin API (node-local authoritative).
    ///
    /// The host was queried directly and returned a live answer.
    /// This is authoritative for the local node's view but may not
    /// reflect the full mesh state.
    HostBacked,

    /// Answer from cached or persisted node-local state.
    ///
    /// The value was retrieved from local storage (e.g. last-known
    /// connector state, cached health snapshot) rather than a live
    /// query. Freshness depends on when the cache was last updated.
    NodeLocal,

    /// Answer derived from static offline artifacts.
    ///
    /// Manifests, registry cache, local history files — artifacts that
    /// exist on disk without requiring any running service.
    Offline,

    /// Answer assembled from partial or stale data.
    ///
    /// One or more preferred sources were queried but returned
    /// incomplete or outdated results. The answer is usable but
    /// should be treated with lower confidence.
    Degraded,

    /// Answer produced by falling back through the resolution chain.
    ///
    /// The preferred sources all failed or were unavailable, and the
    /// resolver used whatever it could find. The decision trace shows
    /// exactly which sources were tried and why they failed.
    FallbackDerived,
}

impl KnowledgeState {
    /// Machine-readable label for structured output.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::MeshBacked => "mesh-backed",
            Self::HostBacked => "host-backed",
            Self::NodeLocal => "node-local",
            Self::Offline => "offline",
            Self::Degraded => "degraded",
            Self::FallbackDerived => "fallback-derived",
        }
    }

    /// Confidence score (0.0–1.0) representing how much weight to give
    /// answers in this state. Higher is more trustworthy.
    #[must_use]
    pub const fn confidence(self) -> f64 {
        match self {
            Self::MeshBacked => 1.0,
            Self::HostBacked => 0.9,
            Self::NodeLocal => 0.6,
            Self::Offline => 0.4,
            Self::Degraded => 0.3,
            Self::FallbackDerived => 0.1,
        }
    }

    /// Whether this state represents live (non-cached) data.
    #[must_use]
    pub const fn is_live(self) -> bool {
        matches!(self, Self::MeshBacked | Self::HostBacked)
    }

    /// Convert to the existing [`IntentProvenance`] for backward
    /// compatibility with the intent compiler surface.
    #[must_use]
    pub const fn to_intent_provenance(self) -> IntentProvenance {
        match self {
            Self::MeshBacked => IntentProvenance::MeshBacked,
            Self::HostBacked => IntentProvenance::HostBacked,
            Self::NodeLocal | Self::Offline => IntentProvenance::Offline,
            Self::Degraded | Self::FallbackDerived => IntentProvenance::Degraded,
        }
    }
}

impl fmt::Display for KnowledgeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Truth Freshness
// ─────────────────────────────────────────────────────────────────────────────

/// Freshness metadata for a resolved truth answer.
///
/// Captures when the answer was produced, how old it is allowed to be
/// before it should be considered stale, and the wall-clock time the
/// resolution took.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TruthFreshness {
    /// When the underlying data was last observed or committed.
    pub observed_at: DateTime<Utc>,
    /// Maximum age before this answer should be re-resolved.
    pub max_age: Duration,
    /// Wall-clock time the resolution took.
    pub resolution_elapsed: Duration,
}

impl TruthFreshness {
    /// Create freshness metadata for a value observed right now.
    #[must_use]
    pub fn now(max_age: Duration, elapsed: Duration) -> Self {
        Self {
            observed_at: Utc::now(),
            max_age,
            resolution_elapsed: elapsed,
        }
    }

    /// Whether this answer has exceeded its maximum age.
    #[must_use]
    pub fn is_stale(&self) -> bool {
        let age = Utc::now()
            .signed_duration_since(self.observed_at)
            .to_std()
            .unwrap_or(Duration::ZERO);
        age > self.max_age
    }

    /// How old this answer is, as a duration since observation.
    #[must_use]
    pub fn age(&self) -> Duration {
        Utc::now()
            .signed_duration_since(self.observed_at)
            .to_std()
            .unwrap_or(Duration::ZERO)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Source Query Outcome
// ─────────────────────────────────────────────────────────────────────────────

/// Outcome of querying a single truth source during resolution.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourceAttempt {
    /// Which source was queried.
    pub source: KnowledgeState,
    /// Whether the query succeeded.
    pub outcome: SourceOutcome,
    /// Wall-clock time this attempt took.
    pub elapsed: Duration,
    /// Optional diagnostic message explaining the outcome.
    pub detail: Option<String>,
}

/// Result of a single source query.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceOutcome {
    /// Source returned a usable answer.
    Success,
    /// Source returned partial or stale data.
    Partial,
    /// Source was unreachable (timeout, connection refused, etc.).
    Unreachable,
    /// Source returned an error.
    Error,
    /// Source was not queried (skipped by strategy or not applicable).
    Skipped,
    /// Source is not configured or not available in this environment.
    NotConfigured,
}

impl SourceOutcome {
    /// Whether this outcome produced usable data.
    #[must_use]
    pub const fn is_usable(self) -> bool {
        matches!(self, Self::Success | Self::Partial)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Evidence Handles
// ─────────────────────────────────────────────────────────────────────────────

/// A handle pointing to durable evidence backing a truth resolution.
///
/// Evidence handles let operators and agents inspect *why* a particular
/// answer was produced. Each handle carries enough information to locate
/// the evidence artifact without embedding the artifact itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum EvidenceHandle {
    /// Reference to a mesh object by content-addressed ID.
    MeshObject {
        /// Hex-encoded 32-byte object ID.
        object_id: String,
        /// Human-readable description of what this object contains.
        description: String,
    },
    /// Reference to an audit event in the zone's audit chain.
    AuditEvent {
        /// Zone where the audit event lives.
        zone_id: String,
        /// Monotonic sequence number in the audit chain.
        seq: u64,
        /// Correlation ID linking related events.
        correlation_id: String,
    },
    /// Reference to a host admin API endpoint for live inspection.
    HostEndpoint {
        /// The API path (e.g. "/health", "/rpc/admin/status").
        path: String,
        /// Optional query parameters for scoping.
        query: Option<String>,
    },
    /// Reference to a local file artifact (manifest, cache, log).
    LocalArtifact {
        /// Filesystem path to the artifact.
        path: String,
        /// What kind of artifact this is.
        artifact_type: ArtifactType,
    },
    /// Reference to an operation receipt proving execution.
    OperationReceipt {
        /// Hex-encoded object ID of the receipt.
        receipt_id: String,
        /// The idempotency key if present.
        idempotency_key: Option<String>,
    },
}

impl EvidenceHandle {
    /// Machine-readable kind tag.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::MeshObject { .. } => "mesh-object",
            Self::AuditEvent { .. } => "audit-event",
            Self::HostEndpoint { .. } => "host-endpoint",
            Self::LocalArtifact { .. } => "local-artifact",
            Self::OperationReceipt { .. } => "operation-receipt",
        }
    }

    /// Whether this handle points to durable (mesh-persisted) evidence.
    #[must_use]
    pub fn is_durable(&self) -> bool {
        matches!(
            self,
            Self::MeshObject { .. } | Self::AuditEvent { .. } | Self::OperationReceipt { .. }
        )
    }
}

/// Type of local artifact referenced by an evidence handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactType {
    /// Connector manifest file.
    Manifest,
    /// Registry cache entry.
    RegistryCache,
    /// Local health snapshot.
    HealthSnapshot,
    /// History/invocation log.
    HistoryLog,
    /// Configuration file.
    Config,
}

/// Evidence metadata attached to a truth resolution.
///
/// Bundles zero or more evidence handles with a correlation ID so the
/// entire resolution can be traced through audit logs and mesh objects.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvidenceMetadata {
    /// Unique correlation ID for this resolution. Links to audit events,
    /// operation receipts, and mesh objects produced during the query.
    pub correlation_id: Uuid,
    /// Evidence handles pointing to artifacts that back this answer.
    pub handles: Vec<EvidenceHandle>,
    /// Retrieval path for deeper inspection (e.g. `fwc trace <id>`).
    pub retrieval_hint: Option<String>,
}

impl EvidenceMetadata {
    /// Create metadata with a fresh correlation ID and no handles.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            correlation_id: Uuid::new_v4(),
            handles: Vec::new(),
            retrieval_hint: None,
        }
    }

    /// Create metadata with a specific correlation ID.
    #[must_use]
    pub fn with_correlation_id(correlation_id: Uuid) -> Self {
        Self {
            correlation_id,
            handles: Vec::new(),
            retrieval_hint: None,
        }
    }

    /// Add an evidence handle.
    pub fn add_handle(&mut self, handle: EvidenceHandle) {
        self.handles.push(handle);
    }

    /// Set the retrieval hint for deeper inspection.
    pub fn set_retrieval_hint(&mut self, hint: impl Into<String>) {
        self.retrieval_hint = Some(hint.into());
    }

    /// Whether any durable evidence backs this resolution.
    #[must_use]
    pub fn has_durable_evidence(&self) -> bool {
        self.handles.iter().any(EvidenceHandle::is_durable)
    }

    /// Count of evidence handles.
    #[must_use]
    pub fn handle_count(&self) -> usize {
        self.handles.len()
    }
}

impl Default for EvidenceMetadata {
    fn default() -> Self {
        Self::empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Decision Trace
// ─────────────────────────────────────────────────────────────────────────────

/// Machine-readable trace of the resolution process.
///
/// Records which sources were queried, in what order, which succeeded or
/// failed, and which source was ultimately selected. Acceptance tests
/// can assert on this trace to verify resolver ordering and fallback
/// semantics.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecisionTrace {
    /// Ordered list of source attempts (in query order).
    pub attempts: Vec<SourceAttempt>,
    /// Which source was ultimately selected.
    pub selected_source: KnowledgeState,
    /// The resolution strategy that was used.
    pub strategy: ResolutionStrategy,
    /// Human-readable explanation of why this source was selected.
    pub reason: String,
    /// Whether the resolver fell back from its preferred source.
    pub used_fallback: bool,
    /// Correlation ID linking this trace to audit events.
    pub correlation_id: Uuid,
}

impl DecisionTrace {
    /// Sources that were successfully queried.
    #[must_use]
    pub fn successful_sources(&self) -> Vec<KnowledgeState> {
        self.attempts
            .iter()
            .filter(|a| a.outcome == SourceOutcome::Success)
            .map(|a| a.source)
            .collect()
    }

    /// Sources that failed or were unreachable.
    #[must_use]
    pub fn failed_sources(&self) -> Vec<KnowledgeState> {
        self.attempts
            .iter()
            .filter(|a| matches!(a.outcome, SourceOutcome::Unreachable | SourceOutcome::Error))
            .map(|a| a.source)
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Truth Resolution
// ─────────────────────────────────────────────────────────────────────────────

/// A resolved truth answer with full provenance and decision metadata.
///
/// Wraps any value `T` with knowledge state classification, freshness
/// tracking, and a decision trace explaining how the answer was produced.
/// This is the primary return type for all resolver queries.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TruthResolution<T> {
    /// The resolved value.
    pub value: T,
    /// What kind of knowledge this answer represents.
    pub knowledge_state: KnowledgeState,
    /// Freshness metadata.
    pub freshness: TruthFreshness,
    /// Full decision trace for audit and debugging.
    pub trace: DecisionTrace,
    /// Evidence handles linking this answer to durable artifacts.
    pub evidence: EvidenceMetadata,
}

impl<T> TruthResolution<T> {
    /// Create a resolution with the given value and metadata.
    #[must_use]
    pub fn new(
        value: T,
        knowledge_state: KnowledgeState,
        freshness: TruthFreshness,
        trace: DecisionTrace,
    ) -> Self {
        let evidence = EvidenceMetadata::with_correlation_id(trace.correlation_id);
        Self {
            value,
            knowledge_state,
            freshness,
            trace,
            evidence,
        }
    }

    /// Map the inner value, preserving all metadata.
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> TruthResolution<U> {
        TruthResolution {
            value: f(self.value),
            knowledge_state: self.knowledge_state,
            freshness: self.freshness,
            trace: self.trace,
            evidence: self.evidence,
        }
    }

    /// Add an evidence handle to this resolution.
    pub fn with_evidence_handle(mut self, handle: EvidenceHandle) -> Self {
        self.evidence.add_handle(handle);
        self
    }

    /// Set the retrieval hint for deeper inspection.
    pub fn with_retrieval_hint(mut self, hint: impl Into<String>) -> Self {
        self.evidence.set_retrieval_hint(hint);
        self
    }

    /// Whether this resolution has durable evidence backing.
    #[must_use]
    pub fn has_durable_evidence(&self) -> bool {
        self.evidence.has_durable_evidence()
    }

    /// The correlation ID linking this resolution to audit events.
    #[must_use]
    pub fn correlation_id(&self) -> Uuid {
        self.evidence.correlation_id
    }

    /// Whether this resolution used a fallback source.
    #[must_use]
    pub fn is_fallback(&self) -> bool {
        self.trace.used_fallback
    }

    /// Whether the resolved data is still fresh.
    #[must_use]
    pub fn is_fresh(&self) -> bool {
        !self.freshness.is_stale()
    }

    /// The backward-compatible [`IntentProvenance`] for this resolution.
    #[must_use]
    pub fn intent_provenance(&self) -> IntentProvenance {
        self.knowledge_state.to_intent_provenance()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Resolution Strategy
// ─────────────────────────────────────────────────────────────────────────────

/// Strategy for resolving truth across multiple sources.
///
/// Determines the precedence order for querying truth sources and how
/// the resolver handles degraded or unavailable sources.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResolutionStrategy {
    /// Query mesh first, then host, then node-local, then offline.
    /// This is the target-state default for mesh-native operation.
    BestAvailable,
    /// Query host first (lower latency), then mesh, then local.
    /// This is the transitional default for host-first operation.
    PreferHost,
    /// Only use offline artifacts. No network queries.
    OfflineOnly,
    /// Only use node-local and offline sources. No mesh or host queries.
    NodeLocalOnly,
}

impl ResolutionStrategy {
    /// The ordered list of sources this strategy will try.
    #[must_use]
    pub fn source_order(self) -> Vec<KnowledgeState> {
        match self {
            Self::BestAvailable => vec![
                KnowledgeState::MeshBacked,
                KnowledgeState::HostBacked,
                KnowledgeState::NodeLocal,
                KnowledgeState::Offline,
            ],
            Self::PreferHost => vec![
                KnowledgeState::HostBacked,
                KnowledgeState::MeshBacked,
                KnowledgeState::NodeLocal,
                KnowledgeState::Offline,
            ],
            Self::OfflineOnly => vec![KnowledgeState::Offline],
            Self::NodeLocalOnly => vec![KnowledgeState::NodeLocal, KnowledgeState::Offline],
        }
    }

    /// Derive a strategy from the existing [`CommandTruthSource`]
    /// classification.
    #[must_use]
    pub fn from_command_truth_source(source: CommandTruthSource) -> Self {
        match source {
            CommandTruthSource::LiveHost => Self::PreferHost,
            CommandTruthSource::OfflineArtifact => Self::OfflineOnly,
            CommandTruthSource::Hybrid => Self::BestAvailable,
            CommandTruthSource::Passthrough => Self::PreferHost,
        }
    }
}

impl Default for ResolutionStrategy {
    fn default() -> Self {
        Self::PreferHost
    }
}

impl fmt::Display for ResolutionStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BestAvailable => f.write_str("best-available"),
            Self::PreferHost => f.write_str("prefer-host"),
            Self::OfflineOnly => f.write_str("offline-only"),
            Self::NodeLocalOnly => f.write_str("node-local-only"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Resolution Error
// ─────────────────────────────────────────────────────────────────────────────

/// Error returned when truth resolution fails across all sources.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolutionError {
    /// Which strategy was attempted.
    pub strategy: ResolutionStrategy,
    /// The attempts that were made before giving up.
    pub attempts: Vec<SourceAttempt>,
    /// Human-readable summary of why resolution failed.
    pub reason: String,
}

impl fmt::Display for ResolutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "truth resolution failed ({} strategy, {} sources tried): {}",
            self.strategy,
            self.attempts.len(),
            self.reason
        )
    }
}

impl std::error::Error for ResolutionError {}

// ─────────────────────────────────────────────────────────────────────────────
// Live Truth Resolver
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the live-truth resolver.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolverConfig {
    /// Default resolution strategy.
    pub default_strategy: ResolutionStrategy,
    /// Maximum age for mesh-backed answers before re-resolution.
    pub mesh_max_age: Duration,
    /// Maximum age for host-backed answers.
    pub host_max_age: Duration,
    /// Maximum age for node-local cached answers.
    pub node_local_max_age: Duration,
    /// Timeout for individual source queries.
    pub source_timeout: Duration,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            default_strategy: ResolutionStrategy::PreferHost,
            mesh_max_age: Duration::from_secs(300), // 5 minutes
            host_max_age: Duration::from_secs(30),  // 30 seconds
            node_local_max_age: Duration::from_secs(60), // 1 minute
            source_timeout: Duration::from_secs(5),
        }
    }
}

/// The mesh-aware live-truth resolver.
///
/// Resolves runtime truth by querying multiple sources in precedence
/// order and wrapping the result with provenance metadata. Each
/// resolution produces a [`TruthResolution`] carrying the answer, its
/// [`KnowledgeState`], [`TruthFreshness`], and a [`DecisionTrace`].
///
/// # Resolution Algorithm
///
/// 1. Determine source order from the [`ResolutionStrategy`]
/// 2. Query each source in order until one succeeds
/// 3. If a source returns partial data, record it and continue
/// 4. Select the best available answer
/// 5. Wrap the answer with provenance and freshness metadata
/// 6. Return the [`TruthResolution`] with the full [`DecisionTrace`]
///
/// # Example
///
/// ```rust,ignore
/// let resolver = LiveTruthResolver::new(ResolverConfig::default());
/// let resolution = resolver.resolve_sync(
///     ResolutionStrategy::PreferHost,
///     |source| match source {
///         KnowledgeState::HostBacked => Some("live-status".to_string()),
///         KnowledgeState::Offline => Some("cached-status".to_string()),
///         _ => None,
///     },
/// );
/// assert_eq!(resolution.knowledge_state, KnowledgeState::HostBacked);
/// ```
pub struct LiveTruthResolver {
    config: ResolverConfig,
}

impl LiveTruthResolver {
    /// Create a resolver with the given configuration.
    #[must_use]
    pub fn new(config: ResolverConfig) -> Self {
        Self { config }
    }

    /// Create a resolver with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(ResolverConfig::default())
    }

    /// The resolver's current configuration.
    #[must_use]
    pub fn config(&self) -> &ResolverConfig {
        &self.config
    }

    /// Resolve truth synchronously using a closure that queries each source.
    ///
    /// The `query_fn` receives a [`KnowledgeState`] indicating which source
    /// to query and returns `Some(value)` on success or `None` on failure.
    /// The resolver calls it in the order determined by the strategy.
    pub fn resolve_sync<T, F>(
        &self,
        strategy: ResolutionStrategy,
        mut query_fn: F,
    ) -> Result<TruthResolution<T>, ResolutionError>
    where
        F: FnMut(KnowledgeState) -> Option<T>,
    {
        let start = Instant::now();
        let sources = strategy.source_order();
        let mut attempts = Vec::with_capacity(sources.len());

        for source in &sources {
            let attempt_start = Instant::now();
            let result = query_fn(*source);
            let attempt_elapsed = attempt_start.elapsed();

            match result {
                Some(value) => {
                    attempts.push(SourceAttempt {
                        source: *source,
                        outcome: SourceOutcome::Success,
                        elapsed: attempt_elapsed,
                        detail: None,
                    });

                    let freshness = TruthFreshness::now(self.max_age_for(*source), start.elapsed());

                    let trace = DecisionTrace {
                        attempts,
                        selected_source: *source,
                        strategy,
                        reason: format!("{} returned a complete answer", source.label()),
                        used_fallback: *source != sources[0],
                        correlation_id: Uuid::new_v4(),
                    };

                    return Ok(TruthResolution::new(value, *source, freshness, trace));
                }
                None => {
                    attempts.push(SourceAttempt {
                        source: *source,
                        outcome: SourceOutcome::Unreachable,
                        elapsed: attempt_elapsed,
                        detail: Some(format!("{} did not return data", source.label())),
                    });
                }
            }
        }

        Err(ResolutionError {
            strategy,
            attempts,
            reason: "all sources failed or were unavailable".into(),
        })
    }

    /// Resolve truth with a closure that can return partial results.
    ///
    /// The `query_fn` returns a [`QueryResult`] that distinguishes between
    /// full success, partial data, and failure.
    pub fn resolve_with_partials<T, F>(
        &self,
        strategy: ResolutionStrategy,
        mut query_fn: F,
    ) -> Result<TruthResolution<T>, ResolutionError>
    where
        F: FnMut(KnowledgeState) -> QueryResult<T>,
    {
        let start = Instant::now();
        let sources = strategy.source_order();
        let mut attempts = Vec::with_capacity(sources.len());
        let mut best_partial: Option<(T, KnowledgeState, Duration)> = None;

        for source in &sources {
            let attempt_start = Instant::now();
            let result = query_fn(*source);
            let attempt_elapsed = attempt_start.elapsed();

            match result {
                QueryResult::Complete(value) => {
                    attempts.push(SourceAttempt {
                        source: *source,
                        outcome: SourceOutcome::Success,
                        elapsed: attempt_elapsed,
                        detail: None,
                    });

                    let freshness = TruthFreshness::now(self.max_age_for(*source), start.elapsed());

                    let trace = DecisionTrace {
                        attempts,
                        selected_source: *source,
                        strategy,
                        reason: format!("{} returned a complete answer", source.label()),
                        used_fallback: *source != sources[0],
                        correlation_id: Uuid::new_v4(),
                    };

                    return Ok(TruthResolution::new(value, *source, freshness, trace));
                }
                QueryResult::Partial(value, detail) => {
                    attempts.push(SourceAttempt {
                        source: *source,
                        outcome: SourceOutcome::Partial,
                        elapsed: attempt_elapsed,
                        detail: Some(detail),
                    });
                    if best_partial.is_none() {
                        best_partial = Some((value, *source, attempt_elapsed));
                    }
                }
                QueryResult::Unavailable(reason) => {
                    attempts.push(SourceAttempt {
                        source: *source,
                        outcome: SourceOutcome::Unreachable,
                        elapsed: attempt_elapsed,
                        detail: Some(reason),
                    });
                }
                QueryResult::Error(reason) => {
                    attempts.push(SourceAttempt {
                        source: *source,
                        outcome: SourceOutcome::Error,
                        elapsed: attempt_elapsed,
                        detail: Some(reason),
                    });
                }
                QueryResult::NotConfigured => {
                    attempts.push(SourceAttempt {
                        source: *source,
                        outcome: SourceOutcome::NotConfigured,
                        elapsed: attempt_elapsed,
                        detail: None,
                    });
                }
            }
        }

        // Use the best partial result as a degraded answer
        if let Some((value, source, _elapsed)) = best_partial {
            let freshness = TruthFreshness::now(self.max_age_for(source), start.elapsed());

            let trace = DecisionTrace {
                attempts,
                selected_source: source,
                strategy,
                reason: format!(
                    "using partial data from {} (degraded: all preferred sources failed or returned incomplete data)",
                    source.label()
                ),
                used_fallback: true,
                correlation_id: Uuid::new_v4(),
            };

            return Ok(TruthResolution::new(
                value,
                KnowledgeState::Degraded,
                freshness,
                trace,
            ));
        }

        Err(ResolutionError {
            strategy,
            attempts,
            reason: "all sources failed or were unavailable".into(),
        })
    }

    /// Build an offline-only resolution without querying any live source.
    ///
    /// Convenience method for commands that are known to be offline-only.
    #[must_use]
    pub fn resolve_offline<T>(value: T) -> TruthResolution<T> {
        let freshness = TruthFreshness::now(
            Duration::from_secs(3600), // offline artifacts are long-lived
            Duration::ZERO,
        );

        let trace = DecisionTrace {
            attempts: vec![SourceAttempt {
                source: KnowledgeState::Offline,
                outcome: SourceOutcome::Success,
                elapsed: Duration::ZERO,
                detail: None,
            }],
            selected_source: KnowledgeState::Offline,
            strategy: ResolutionStrategy::OfflineOnly,
            reason: "offline artifact (no live sources queried)".into(),
            used_fallback: false,
            correlation_id: Uuid::new_v4(),
        };

        TruthResolution::new(value, KnowledgeState::Offline, freshness, trace)
    }

    /// Build a host-backed resolution for a direct host API response.
    ///
    /// Convenience method for commands that only query the host.
    #[must_use]
    pub fn resolve_host_direct<T>(value: T, elapsed: Duration) -> TruthResolution<T> {
        let freshness = TruthFreshness::now(Duration::from_secs(30), elapsed);

        let trace = DecisionTrace {
            attempts: vec![SourceAttempt {
                source: KnowledgeState::HostBacked,
                outcome: SourceOutcome::Success,
                elapsed,
                detail: None,
            }],
            selected_source: KnowledgeState::HostBacked,
            strategy: ResolutionStrategy::PreferHost,
            reason: "live host admin API response".into(),
            used_fallback: false,
            correlation_id: Uuid::new_v4(),
        };

        TruthResolution::new(value, KnowledgeState::HostBacked, freshness, trace)
    }

    /// Maximum age for answers from a given source.
    fn max_age_for(&self, source: KnowledgeState) -> Duration {
        match source {
            KnowledgeState::MeshBacked => self.config.mesh_max_age,
            KnowledgeState::HostBacked => self.config.host_max_age,
            KnowledgeState::NodeLocal => self.config.node_local_max_age,
            KnowledgeState::Offline => Duration::from_secs(3600),
            KnowledgeState::Degraded | KnowledgeState::FallbackDerived => Duration::from_secs(10),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Query Result
// ─────────────────────────────────────────────────────────────────────────────

/// Result of querying a single truth source.
///
/// Richer than `Option<T>` — distinguishes complete answers, partial data,
/// unavailability, errors, and unconfigured sources.
pub enum QueryResult<T> {
    /// Source returned a complete, usable answer.
    Complete(T),
    /// Source returned partial or stale data (with explanation).
    Partial(T, String),
    /// Source is unreachable (timeout, connection refused).
    Unavailable(String),
    /// Source returned an error.
    Error(String),
    /// Source is not configured in this environment.
    NotConfigured,
}

// ─────────────────────────────────────────────────────────────────────────────
// Operator Evidence Lookup Model (o8umn.1)
// ─────────────────────────────────────────────────────────────────────────────

/// Which operator command produced an evidence-backed output.
///
/// Used to tag evidence lookups so the model is consistent across all
/// operator-facing commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperatorCommand {
    /// `fwc doctor` — connector health diagnostics.
    Doctor,
    /// `fwc preflight` — pre-invocation risk assessment.
    Preflight,
    /// `fwc show` — connector detail introspection.
    Show,
    /// `fwc health` — fleet health dashboard.
    Health,
    /// `fwc explain` — why-did-this-happen reasoning.
    Explain,
    /// `fwc status` — connector runtime status.
    Status,
}

impl OperatorCommand {
    /// The evidence retrieval command for deeper inspection.
    #[must_use]
    pub fn drill_down_hint(self, correlation_id: &Uuid) -> String {
        match self {
            Self::Doctor => format!("fwc trace --correlation {correlation_id} --type doctor"),
            Self::Preflight => {
                format!("fwc trace --correlation {correlation_id} --type preflight")
            }
            Self::Show => format!("fwc trace --correlation {correlation_id} --type show"),
            Self::Health => format!("fwc trace --correlation {correlation_id} --type health"),
            Self::Explain => format!("fwc trace --correlation {correlation_id} --type explain"),
            Self::Status => format!("fwc trace --correlation {correlation_id} --type status"),
        }
    }
}

/// A next-step action that an operator can take after reading evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrillDownAction {
    /// Human-readable label for the action.
    pub label: String,
    /// The CLI command to run (e.g. `fwc trace --object abc123`).
    pub command: String,
    /// Why this action would be helpful.
    pub rationale: String,
}

/// Shared evidence-lookup contract for operator commands.
///
/// Every operator command (doctor, preflight, show, health, explain)
/// uses this model to structure its evidence-backed output. The model
/// provides consistent fields for:
///
/// - **Bundle discovery**: How to find the evidence backing an answer
/// - **Correlation**: UUID linking to audit events and trace contexts
/// - **Drill-down**: Next-step commands for deeper inspection
/// - **Remediation**: Suggested fixes when issues are found
///
/// This contract is the shared foundation that docs and support flows
/// teach once, rather than inventing per-command evidence semantics.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorEvidenceLookup {
    /// Which operator command produced this lookup.
    pub command: OperatorCommand,
    /// The connector being inspected (if applicable).
    pub connector_id: Option<String>,
    /// The underlying truth resolution with full provenance.
    pub knowledge_state: KnowledgeState,
    /// Correlation ID for audit trail linkage.
    pub correlation_id: Uuid,
    /// Evidence handles backing this output.
    pub evidence_handles: Vec<EvidenceHandle>,
    /// Next-step drill-down actions the operator can take.
    pub drill_down: Vec<DrillDownAction>,
    /// The primary retrieval command for this evidence.
    pub retrieval_command: String,
}

impl OperatorEvidenceLookup {
    /// Create a new lookup for a given command and resolution.
    pub fn from_resolution<T>(
        command: OperatorCommand,
        connector_id: Option<String>,
        resolution: &TruthResolution<T>,
    ) -> Self {
        let correlation_id = resolution.correlation_id();
        let retrieval_command = command.drill_down_hint(&correlation_id);

        Self {
            command,
            connector_id,
            knowledge_state: resolution.knowledge_state,
            correlation_id,
            evidence_handles: resolution.evidence.handles.clone(),
            drill_down: Vec::new(),
            retrieval_command,
        }
    }

    /// Add a drill-down action.
    pub fn add_drill_down(
        &mut self,
        label: impl Into<String>,
        command: impl Into<String>,
        rationale: impl Into<String>,
    ) {
        self.drill_down.push(DrillDownAction {
            label: label.into(),
            command: command.into(),
            rationale: rationale.into(),
        });
    }

    /// Whether this lookup has durable evidence.
    #[must_use]
    pub fn has_durable_evidence(&self) -> bool {
        self.evidence_handles.iter().any(EvidenceHandle::is_durable)
    }

    /// How many drill-down actions are available.
    #[must_use]
    pub fn drill_down_count(&self) -> usize {
        self.drill_down.len()
    }

    /// Serialize to a structured JSON log entry for operator output.
    #[must_use]
    pub fn to_structured_log(&self) -> serde_json::Value {
        serde_json::json!({
            "command": serde_json::to_value(self.command).unwrap_or_default(),
            "connector_id": self.connector_id,
            "knowledge_state": self.knowledge_state.label(),
            "confidence": self.knowledge_state.confidence(),
            "is_live": self.knowledge_state.is_live(),
            "correlation_id": self.correlation_id.to_string(),
            "evidence_count": self.evidence_handles.len(),
            "has_durable_evidence": self.has_durable_evidence(),
            "retrieval_command": self.retrieval_command,
            "drill_down": self.drill_down.iter().map(|d| serde_json::json!({
                "label": d.label,
                "command": d.command,
                "rationale": d.rationale,
            })).collect::<Vec<_>>(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Remediation-Aware Operator Output (o8umn.2)
// ─────────────────────────────────────────────────────────────────────────────

/// Severity of a remediation finding, aligned with doctor.rs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RemediationSeverity {
    /// Informational — context for the operator.
    Info,
    /// Warning — should be investigated.
    Warning,
    /// Error — action needed.
    Error,
    /// Critical — immediate action required.
    Critical,
}

impl RemediationSeverity {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }
}

/// A single remediation finding with evidence linkage.
///
/// Extends the existing `Diagnosis` model by linking each finding to
/// evidence handles and providing structured next-step guidance.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RemediationFinding {
    /// What was found.
    pub summary: String,
    /// Detailed explanation for deep drill-down.
    pub detail: Option<String>,
    /// Severity of this finding.
    pub severity: RemediationSeverity,
    /// The evidence handle that backs this finding.
    pub evidence: Option<EvidenceHandle>,
    /// Suggested next actions (commands or manual steps).
    pub next_actions: Vec<DrillDownAction>,
}

/// Complete remediation-aware output for an operator command.
///
/// This is the top-level return type for evidence-backed operator
/// commands. It combines:
/// - A concise summary suitable for terminal output
/// - Evidence-backed findings with remediation guidance
/// - The underlying evidence lookup for audit linkage
///
/// All six operator commands (doctor, preflight, show, health, explain,
/// status) produce this same output shape, so docs and support flows
/// can teach it once.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RemediationOutput {
    /// The evidence lookup that produced this output.
    pub evidence_lookup: OperatorEvidenceLookup,
    /// One-line summary for compact display (e.g. TOON format).
    pub summary: String,
    /// Ordered findings from most to least severe.
    pub findings: Vec<RemediationFinding>,
    /// Overall status: did we find issues?
    pub has_issues: bool,
    /// Count of findings by severity.
    pub severity_counts: SeverityCounts,
}

/// Count of findings by severity level.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct SeverityCounts {
    pub critical: usize,
    pub error: usize,
    pub warning: usize,
    pub info: usize,
}

impl SeverityCounts {
    #[must_use]
    pub fn total(&self) -> usize {
        self.critical + self.error + self.warning + self.info
    }
}

impl RemediationOutput {
    /// Create a remediation output from an evidence lookup.
    pub fn new(evidence_lookup: OperatorEvidenceLookup, summary: impl Into<String>) -> Self {
        Self {
            evidence_lookup,
            summary: summary.into(),
            findings: Vec::new(),
            has_issues: false,
            severity_counts: SeverityCounts::default(),
        }
    }

    /// Add a finding and update severity counts.
    pub fn add_finding(&mut self, finding: RemediationFinding) {
        match finding.severity {
            RemediationSeverity::Critical => self.severity_counts.critical += 1,
            RemediationSeverity::Error => self.severity_counts.error += 1,
            RemediationSeverity::Warning => self.severity_counts.warning += 1,
            RemediationSeverity::Info => self.severity_counts.info += 1,
        }
        if finding.severity >= RemediationSeverity::Warning {
            self.has_issues = true;
        }
        self.findings.push(finding);
    }

    /// Sort findings by severity (critical first).
    pub fn sort_by_severity(&mut self) {
        self.findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    }

    /// Most severe finding, if any.
    #[must_use]
    pub fn worst_finding(&self) -> Option<&RemediationFinding> {
        self.findings.iter().max_by_key(|f| f.severity)
    }

    /// Total number of findings.
    #[must_use]
    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }

    /// Serialize to structured log for operator/agent consumption.
    #[must_use]
    pub fn to_structured_log(&self) -> serde_json::Value {
        serde_json::json!({
            "command": serde_json::to_value(self.evidence_lookup.command).unwrap_or_default(),
            "connector_id": self.evidence_lookup.connector_id,
            "summary": self.summary,
            "knowledge_state": self.evidence_lookup.knowledge_state.label(),
            "has_issues": self.has_issues,
            "severity_counts": {
                "critical": self.severity_counts.critical,
                "error": self.severity_counts.error,
                "warning": self.severity_counts.warning,
                "info": self.severity_counts.info,
            },
            "correlation_id": self.evidence_lookup.correlation_id.to_string(),
            "retrieval_command": self.evidence_lookup.retrieval_command,
            "findings": self.findings.iter().map(|f| serde_json::json!({
                "severity": f.severity.label(),
                "summary": f.summary,
                "detail": f.detail,
                "has_evidence": f.evidence.is_some(),
                "next_actions": f.next_actions.len(),
            })).collect::<Vec<_>>(),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── KnowledgeState ────────────────────────────────────────────────

    #[test]
    fn knowledge_state_labels_are_kebab_case() {
        assert_eq!(KnowledgeState::MeshBacked.label(), "mesh-backed");
        assert_eq!(KnowledgeState::HostBacked.label(), "host-backed");
        assert_eq!(KnowledgeState::NodeLocal.label(), "node-local");
        assert_eq!(KnowledgeState::Offline.label(), "offline");
        assert_eq!(KnowledgeState::Degraded.label(), "degraded");
        assert_eq!(KnowledgeState::FallbackDerived.label(), "fallback-derived");
    }

    #[test]
    fn knowledge_state_confidence_ordering() {
        assert!(KnowledgeState::MeshBacked.confidence() > KnowledgeState::HostBacked.confidence());
        assert!(KnowledgeState::HostBacked.confidence() > KnowledgeState::NodeLocal.confidence());
        assert!(KnowledgeState::NodeLocal.confidence() > KnowledgeState::Offline.confidence());
        assert!(KnowledgeState::Offline.confidence() > KnowledgeState::Degraded.confidence());
        assert!(
            KnowledgeState::Degraded.confidence() > KnowledgeState::FallbackDerived.confidence()
        );
    }

    #[test]
    fn knowledge_state_is_live() {
        assert!(KnowledgeState::MeshBacked.is_live());
        assert!(KnowledgeState::HostBacked.is_live());
        assert!(!KnowledgeState::NodeLocal.is_live());
        assert!(!KnowledgeState::Offline.is_live());
        assert!(!KnowledgeState::Degraded.is_live());
        assert!(!KnowledgeState::FallbackDerived.is_live());
    }

    #[test]
    fn knowledge_state_to_intent_provenance() {
        assert_eq!(
            KnowledgeState::MeshBacked.to_intent_provenance(),
            IntentProvenance::MeshBacked
        );
        assert_eq!(
            KnowledgeState::HostBacked.to_intent_provenance(),
            IntentProvenance::HostBacked
        );
        assert_eq!(
            KnowledgeState::NodeLocal.to_intent_provenance(),
            IntentProvenance::Offline
        );
        assert_eq!(
            KnowledgeState::Offline.to_intent_provenance(),
            IntentProvenance::Offline
        );
        assert_eq!(
            KnowledgeState::Degraded.to_intent_provenance(),
            IntentProvenance::Degraded
        );
        assert_eq!(
            KnowledgeState::FallbackDerived.to_intent_provenance(),
            IntentProvenance::Degraded
        );
    }

    #[test]
    fn knowledge_state_display() {
        assert_eq!(format!("{}", KnowledgeState::MeshBacked), "mesh-backed");
        assert_eq!(
            format!("{}", KnowledgeState::FallbackDerived),
            "fallback-derived"
        );
    }

    #[test]
    fn knowledge_state_serde_roundtrip() {
        for state in [
            KnowledgeState::MeshBacked,
            KnowledgeState::HostBacked,
            KnowledgeState::NodeLocal,
            KnowledgeState::Offline,
            KnowledgeState::Degraded,
            KnowledgeState::FallbackDerived,
        ] {
            let json = serde_json::to_string(&state).unwrap();
            let back: KnowledgeState = serde_json::from_str(&json).unwrap();
            assert_eq!(state, back);
        }
    }

    // ── ResolutionStrategy ────────────────────────────────────────────

    #[test]
    fn best_available_source_order() {
        let order = ResolutionStrategy::BestAvailable.source_order();
        assert_eq!(order[0], KnowledgeState::MeshBacked);
        assert_eq!(order[1], KnowledgeState::HostBacked);
        assert_eq!(order[2], KnowledgeState::NodeLocal);
        assert_eq!(order[3], KnowledgeState::Offline);
    }

    #[test]
    fn prefer_host_source_order() {
        let order = ResolutionStrategy::PreferHost.source_order();
        assert_eq!(order[0], KnowledgeState::HostBacked);
        assert_eq!(order[1], KnowledgeState::MeshBacked);
    }

    #[test]
    fn offline_only_source_order() {
        let order = ResolutionStrategy::OfflineOnly.source_order();
        assert_eq!(order.len(), 1);
        assert_eq!(order[0], KnowledgeState::Offline);
    }

    #[test]
    fn node_local_only_source_order() {
        let order = ResolutionStrategy::NodeLocalOnly.source_order();
        assert_eq!(order.len(), 2);
        assert_eq!(order[0], KnowledgeState::NodeLocal);
        assert_eq!(order[1], KnowledgeState::Offline);
    }

    #[test]
    fn strategy_from_command_truth_source() {
        assert_eq!(
            ResolutionStrategy::from_command_truth_source(CommandTruthSource::LiveHost),
            ResolutionStrategy::PreferHost
        );
        assert_eq!(
            ResolutionStrategy::from_command_truth_source(CommandTruthSource::OfflineArtifact),
            ResolutionStrategy::OfflineOnly
        );
        assert_eq!(
            ResolutionStrategy::from_command_truth_source(CommandTruthSource::Hybrid),
            ResolutionStrategy::BestAvailable
        );
        assert_eq!(
            ResolutionStrategy::from_command_truth_source(CommandTruthSource::Passthrough),
            ResolutionStrategy::PreferHost
        );
    }

    #[test]
    fn strategy_serde_roundtrip() {
        for strategy in [
            ResolutionStrategy::BestAvailable,
            ResolutionStrategy::PreferHost,
            ResolutionStrategy::OfflineOnly,
            ResolutionStrategy::NodeLocalOnly,
        ] {
            let json = serde_json::to_string(&strategy).unwrap();
            let back: ResolutionStrategy = serde_json::from_str(&json).unwrap();
            assert_eq!(strategy, back);
        }
    }

    #[test]
    fn strategy_display() {
        assert_eq!(
            format!("{}", ResolutionStrategy::BestAvailable),
            "best-available"
        );
        assert_eq!(format!("{}", ResolutionStrategy::PreferHost), "prefer-host");
        assert_eq!(
            format!("{}", ResolutionStrategy::OfflineOnly),
            "offline-only"
        );
        assert_eq!(
            format!("{}", ResolutionStrategy::NodeLocalOnly),
            "node-local-only"
        );
    }

    // ── TruthFreshness ────────────────────────────────────────────────

    #[test]
    fn freshness_now_is_not_stale() {
        let f = TruthFreshness::now(Duration::from_secs(60), Duration::from_millis(10));
        assert!(!f.is_stale());
        assert!(f.age() < Duration::from_secs(1));
    }

    #[test]
    fn freshness_old_is_stale() {
        let f = TruthFreshness {
            observed_at: Utc::now() - chrono::Duration::seconds(120),
            max_age: Duration::from_secs(60),
            resolution_elapsed: Duration::from_millis(5),
        };
        assert!(f.is_stale());
    }

    // ── SourceOutcome ─────────────────────────────────────────────────

    #[test]
    fn source_outcome_usability() {
        assert!(SourceOutcome::Success.is_usable());
        assert!(SourceOutcome::Partial.is_usable());
        assert!(!SourceOutcome::Unreachable.is_usable());
        assert!(!SourceOutcome::Error.is_usable());
        assert!(!SourceOutcome::Skipped.is_usable());
        assert!(!SourceOutcome::NotConfigured.is_usable());
    }

    // ── LiveTruthResolver: resolve_sync ───────────────────────────────

    #[test]
    fn resolve_sync_first_source_succeeds() {
        let resolver = LiveTruthResolver::with_defaults();
        let result = resolver.resolve_sync(ResolutionStrategy::PreferHost, |source| {
            if source == KnowledgeState::HostBacked {
                Some("live-status")
            } else {
                None
            }
        });

        let resolution = result.unwrap();
        assert_eq!(resolution.value, "live-status");
        assert_eq!(resolution.knowledge_state, KnowledgeState::HostBacked);
        assert!(!resolution.is_fallback());
        assert_eq!(resolution.trace.selected_source, KnowledgeState::HostBacked);
        assert_eq!(resolution.trace.strategy, ResolutionStrategy::PreferHost);
        assert_eq!(resolution.trace.attempts.len(), 1);
    }

    #[test]
    fn resolve_sync_falls_back_to_offline() {
        let resolver = LiveTruthResolver::with_defaults();
        let result = resolver.resolve_sync(ResolutionStrategy::PreferHost, |source| {
            if source == KnowledgeState::Offline {
                Some("cached-manifest")
            } else {
                None
            }
        });

        let resolution = result.unwrap();
        assert_eq!(resolution.value, "cached-manifest");
        assert_eq!(resolution.knowledge_state, KnowledgeState::Offline);
        assert!(resolution.is_fallback());
        assert_eq!(resolution.trace.attempts.len(), 4); // tried all 4 sources
        assert!(resolution.trace.used_fallback);
    }

    #[test]
    fn resolve_sync_mesh_backed_preferred_in_best_available() {
        let resolver = LiveTruthResolver::with_defaults();
        let result =
            resolver.resolve_sync(ResolutionStrategy::BestAvailable, |source| match source {
                KnowledgeState::MeshBacked => Some("mesh-state"),
                KnowledgeState::HostBacked => Some("host-state"),
                _ => None,
            });

        let resolution = result.unwrap();
        assert_eq!(resolution.value, "mesh-state");
        assert_eq!(resolution.knowledge_state, KnowledgeState::MeshBacked);
        assert!(!resolution.is_fallback());
        // Only one attempt recorded (mesh succeeded immediately)
        assert_eq!(resolution.trace.attempts.len(), 1);
    }

    #[test]
    fn resolve_sync_all_fail_returns_error() {
        let resolver = LiveTruthResolver::with_defaults();
        let result: Result<TruthResolution<String>, _> =
            resolver.resolve_sync(ResolutionStrategy::PreferHost, |_| None);

        let err = result.unwrap_err();
        assert_eq!(err.strategy, ResolutionStrategy::PreferHost);
        assert_eq!(err.attempts.len(), 4);
        assert!(err.reason.contains("all sources failed"));
    }

    #[test]
    fn resolve_sync_offline_only_skips_live_sources() {
        let resolver = LiveTruthResolver::with_defaults();
        let mut queried_sources = Vec::new();
        let result = resolver.resolve_sync(ResolutionStrategy::OfflineOnly, |source| {
            queried_sources.push(source);
            if source == KnowledgeState::Offline {
                Some("manifest-data")
            } else {
                None
            }
        });

        let resolution = result.unwrap();
        assert_eq!(resolution.value, "manifest-data");
        assert_eq!(queried_sources, vec![KnowledgeState::Offline]);
        assert!(!resolution.is_fallback());
    }

    #[test]
    fn resolve_sync_decision_trace_records_all_attempts() {
        let resolver = LiveTruthResolver::with_defaults();
        let result = resolver.resolve_sync(ResolutionStrategy::BestAvailable, |source| {
            if source == KnowledgeState::NodeLocal {
                Some("local-cache")
            } else {
                None
            }
        });

        let resolution = result.unwrap();
        assert_eq!(resolution.trace.attempts.len(), 3); // mesh, host, then node-local
        assert_eq!(
            resolution.trace.attempts[0].outcome,
            SourceOutcome::Unreachable
        );
        assert_eq!(
            resolution.trace.attempts[1].outcome,
            SourceOutcome::Unreachable
        );
        assert_eq!(resolution.trace.attempts[2].outcome, SourceOutcome::Success);
        assert!(resolution.is_fallback());
    }

    // ── LiveTruthResolver: resolve_with_partials ──────────────────────

    #[test]
    fn resolve_with_partials_prefers_complete_over_partial() {
        let resolver = LiveTruthResolver::with_defaults();
        let result =
            resolver.resolve_with_partials(ResolutionStrategy::PreferHost, |source| match source {
                KnowledgeState::HostBacked => {
                    QueryResult::Partial("stale-host".into(), "cache expired".into())
                }
                KnowledgeState::MeshBacked => QueryResult::Complete("fresh-mesh".to_string()),
                _ => QueryResult::Unavailable("not configured".into()),
            });

        let resolution = result.unwrap();
        // PreferHost tries host first → gets partial, then mesh → gets complete
        assert_eq!(resolution.value, "fresh-mesh");
        assert_eq!(resolution.knowledge_state, KnowledgeState::MeshBacked);
        assert!(resolution.is_fallback());
    }

    #[test]
    fn resolve_with_partials_uses_partial_when_no_complete() {
        let resolver = LiveTruthResolver::with_defaults();
        let result =
            resolver.resolve_with_partials(ResolutionStrategy::PreferHost, |source| match source {
                KnowledgeState::HostBacked => {
                    QueryResult::<String>::Partial("stale-data".into(), "stale cache".into())
                }
                _ => QueryResult::Unavailable("not available".into()),
            });

        let resolution = result.unwrap();
        assert_eq!(resolution.value, "stale-data");
        assert_eq!(resolution.knowledge_state, KnowledgeState::Degraded);
        assert!(resolution.is_fallback());
    }

    #[test]
    fn resolve_with_partials_not_configured_is_recorded() {
        let resolver = LiveTruthResolver::with_defaults();
        let result = resolver.resolve_with_partials(ResolutionStrategy::OfflineOnly, |_source| {
            QueryResult::<String>::NotConfigured
        });

        let err = result.unwrap_err();
        assert_eq!(err.attempts.len(), 1);
        assert_eq!(err.attempts[0].outcome, SourceOutcome::NotConfigured);
    }

    // ── Convenience constructors ──────────────────────────────────────

    #[test]
    fn resolve_offline_creates_correct_resolution() {
        let resolution = LiveTruthResolver::resolve_offline("manifest.toml contents");
        assert_eq!(resolution.value, "manifest.toml contents");
        assert_eq!(resolution.knowledge_state, KnowledgeState::Offline);
        assert_eq!(resolution.trace.strategy, ResolutionStrategy::OfflineOnly);
        assert!(!resolution.is_fallback());
        assert!(resolution.is_fresh());
    }

    #[test]
    fn resolve_host_direct_creates_correct_resolution() {
        let resolution =
            LiveTruthResolver::resolve_host_direct("healthy", Duration::from_millis(42));
        assert_eq!(resolution.value, "healthy");
        assert_eq!(resolution.knowledge_state, KnowledgeState::HostBacked);
        assert_eq!(resolution.trace.strategy, ResolutionStrategy::PreferHost);
        assert!(!resolution.is_fallback());
    }

    // ── TruthResolution methods ───────────────────────────────────────

    #[test]
    fn resolution_map_preserves_metadata() {
        let resolution = LiveTruthResolver::resolve_offline(42_u32);
        let mapped = resolution.map(|v| v.to_string());
        assert_eq!(mapped.value, "42");
        assert_eq!(mapped.knowledge_state, KnowledgeState::Offline);
    }

    #[test]
    fn resolution_intent_provenance_backward_compat() {
        let resolution = LiveTruthResolver::resolve_offline("test");
        assert_eq!(resolution.intent_provenance(), IntentProvenance::Offline);

        let resolution = LiveTruthResolver::resolve_host_direct("test", Duration::from_millis(1));
        assert_eq!(resolution.intent_provenance(), IntentProvenance::HostBacked);
    }

    // ── DecisionTrace helpers ─────────────────────────────────────────

    #[test]
    fn decision_trace_successful_and_failed_sources() {
        let trace = DecisionTrace {
            attempts: vec![
                SourceAttempt {
                    source: KnowledgeState::MeshBacked,
                    outcome: SourceOutcome::Unreachable,
                    elapsed: Duration::from_millis(100),
                    detail: Some("timeout".into()),
                },
                SourceAttempt {
                    source: KnowledgeState::HostBacked,
                    outcome: SourceOutcome::Success,
                    elapsed: Duration::from_millis(20),
                    detail: None,
                },
            ],
            selected_source: KnowledgeState::HostBacked,
            strategy: ResolutionStrategy::BestAvailable,
            reason: "host-backed returned a complete answer".into(),
            used_fallback: true,
            correlation_id: Uuid::new_v4(),
        };

        assert_eq!(trace.successful_sources(), vec![KnowledgeState::HostBacked]);
        assert_eq!(trace.failed_sources(), vec![KnowledgeState::MeshBacked]);
    }

    // ── ResolutionError ───────────────────────────────────────────────

    #[test]
    fn resolution_error_display() {
        let err = ResolutionError {
            strategy: ResolutionStrategy::PreferHost,
            attempts: vec![SourceAttempt {
                source: KnowledgeState::HostBacked,
                outcome: SourceOutcome::Unreachable,
                elapsed: Duration::from_secs(5),
                detail: Some("connection refused".into()),
            }],
            reason: "host unreachable".into(),
        };
        let display = format!("{err}");
        assert!(display.contains("prefer-host"));
        assert!(display.contains("1 sources tried"));
        assert!(display.contains("host unreachable"));
    }

    // ── ResolverConfig ────────────────────────────────────────────────

    #[test]
    fn default_config_has_sane_values() {
        let config = ResolverConfig::default();
        assert_eq!(config.default_strategy, ResolutionStrategy::PreferHost);
        assert_eq!(config.mesh_max_age, Duration::from_secs(300));
        assert_eq!(config.host_max_age, Duration::from_secs(30));
        assert_eq!(config.node_local_max_age, Duration::from_secs(60));
        assert_eq!(config.source_timeout, Duration::from_secs(5));
    }

    // ── Integration-style scenario tests ──────────────────────────────

    #[test]
    fn scenario_host_down_falls_to_offline() {
        let resolver = LiveTruthResolver::with_defaults();
        let result = resolver.resolve_sync(ResolutionStrategy::PreferHost, |source| match source {
            KnowledgeState::Offline => Some(serde_json::json!({
                "connector": "github",
                "status": "manifest-declared",
                "version": "1.2.3"
            })),
            _ => None,
        });

        let resolution = result.unwrap();
        assert_eq!(resolution.knowledge_state, KnowledgeState::Offline);
        assert!(resolution.is_fallback());
        assert_eq!(resolution.trace.failed_sources().len(), 3);
    }

    #[test]
    fn scenario_mesh_and_host_both_available() {
        let resolver = LiveTruthResolver::with_defaults();
        let result =
            resolver.resolve_sync(ResolutionStrategy::BestAvailable, |source| match source {
                KnowledgeState::MeshBacked => Some("distributed-state"),
                KnowledgeState::HostBacked => Some("local-host-state"),
                _ => None,
            });

        let resolution = result.unwrap();
        // BestAvailable prefers mesh
        assert_eq!(resolution.value, "distributed-state");
        assert_eq!(resolution.knowledge_state, KnowledgeState::MeshBacked);
        assert!(!resolution.is_fallback());
    }

    #[test]
    fn scenario_degraded_host_with_partial_data() {
        let resolver = LiveTruthResolver::with_defaults();
        let result =
            resolver.resolve_with_partials(ResolutionStrategy::PreferHost, |source| match source {
                KnowledgeState::HostBacked => QueryResult::Partial(
                    serde_json::json!({"status": "degraded", "connectors": []}),
                    "host responding but connector enumeration timed out".into(),
                ),
                KnowledgeState::MeshBacked => {
                    QueryResult::Unavailable("mesh not configured".into())
                }
                KnowledgeState::NodeLocal => QueryResult::Unavailable("no local cache".into()),
                KnowledgeState::Offline => QueryResult::Complete(
                    serde_json::json!({"status": "offline", "connectors": ["github", "slack"]}),
                ),
                _ => QueryResult::NotConfigured,
            });

        let resolution = result.unwrap();
        // Complete offline answer beats partial host answer
        assert_eq!(resolution.knowledge_state, KnowledgeState::Offline);
    }

    #[test]
    fn scenario_refusal_when_nothing_available() {
        let resolver = LiveTruthResolver::with_defaults();
        let result: Result<TruthResolution<String>, _> = resolver
            .resolve_with_partials(ResolutionStrategy::PreferHost, |_| {
                QueryResult::Unavailable("not configured".into())
            });

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.attempts.len(), 4);
    }

    #[test]
    fn scenario_node_local_only_never_queries_network() {
        let resolver = LiveTruthResolver::with_defaults();
        let mut queried = Vec::new();
        let result = resolver.resolve_sync(ResolutionStrategy::NodeLocalOnly, |source| {
            queried.push(source);
            match source {
                KnowledgeState::NodeLocal => Some("local-state"),
                KnowledgeState::Offline => Some("manifest"),
                _ => panic!("should not query network sources"),
            }
        });

        let resolution = result.unwrap();
        assert_eq!(resolution.value, "local-state");
        assert_eq!(queried, vec![KnowledgeState::NodeLocal]);
    }

    #[test]
    fn scenario_explain_resolver_decision() {
        // Simulates the `fwc explain` use case: resolver must explain
        // exactly why it chose the answer it did.
        let resolver = LiveTruthResolver::with_defaults();
        let result =
            resolver.resolve_sync(ResolutionStrategy::BestAvailable, |source| match source {
                KnowledgeState::MeshBacked | KnowledgeState::HostBacked => None,
                KnowledgeState::NodeLocal => Some("cached-2m-ago"),
                _ => None,
            });

        let resolution = result.unwrap();
        assert_eq!(resolution.knowledge_state, KnowledgeState::NodeLocal);
        assert!(resolution.is_fallback());

        // The trace explains exactly what happened
        let trace = &resolution.trace;
        assert_eq!(trace.attempts.len(), 3);
        assert_eq!(trace.attempts[0].source, KnowledgeState::MeshBacked);
        assert_eq!(trace.attempts[0].outcome, SourceOutcome::Unreachable);
        assert_eq!(trace.attempts[1].source, KnowledgeState::HostBacked);
        assert_eq!(trace.attempts[1].outcome, SourceOutcome::Unreachable);
        assert_eq!(trace.attempts[2].source, KnowledgeState::NodeLocal);
        assert_eq!(trace.attempts[2].outcome, SourceOutcome::Success);
        assert!(trace.reason.contains("node-local"));
    }

    // ── Evidence handles (kpj16.2) ────────────────────────────────────

    #[test]
    fn evidence_handle_kind_tags() {
        let mesh = EvidenceHandle::MeshObject {
            object_id: "abc123".into(),
            description: "connector state".into(),
        };
        assert_eq!(mesh.kind(), "mesh-object");
        assert!(mesh.is_durable());

        let host = EvidenceHandle::HostEndpoint {
            path: "/health".into(),
            query: None,
        };
        assert_eq!(host.kind(), "host-endpoint");
        assert!(!host.is_durable());

        let local = EvidenceHandle::LocalArtifact {
            path: "/tmp/manifest.toml".into(),
            artifact_type: ArtifactType::Manifest,
        };
        assert_eq!(local.kind(), "local-artifact");
        assert!(!local.is_durable());

        let audit = EvidenceHandle::AuditEvent {
            zone_id: "z:private".into(),
            seq: 42,
            correlation_id: "corr-123".into(),
        };
        assert_eq!(audit.kind(), "audit-event");
        assert!(audit.is_durable());

        let receipt = EvidenceHandle::OperationReceipt {
            receipt_id: "receipt-abc".into(),
            idempotency_key: Some("key-1".into()),
        };
        assert_eq!(receipt.kind(), "operation-receipt");
        assert!(receipt.is_durable());
    }

    #[test]
    fn evidence_handle_serde_roundtrip() {
        let handle = EvidenceHandle::MeshObject {
            object_id: "deadbeef".into(),
            description: "test object".into(),
        };
        let json = serde_json::to_string(&handle).unwrap();
        let back: EvidenceHandle = serde_json::from_str(&json).unwrap();
        assert_eq!(handle, back);
        assert!(json.contains("\"kind\":\"mesh-object\""));
    }

    #[test]
    fn evidence_metadata_empty_has_no_durable() {
        let meta = EvidenceMetadata::empty();
        assert!(!meta.has_durable_evidence());
        assert_eq!(meta.handle_count(), 0);
        assert!(meta.retrieval_hint.is_none());
    }

    #[test]
    fn evidence_metadata_add_handles() {
        let mut meta = EvidenceMetadata::empty();
        meta.add_handle(EvidenceHandle::HostEndpoint {
            path: "/health".into(),
            query: None,
        });
        assert!(!meta.has_durable_evidence());
        assert_eq!(meta.handle_count(), 1);

        meta.add_handle(EvidenceHandle::MeshObject {
            object_id: "abc".into(),
            description: "state".into(),
        });
        assert!(meta.has_durable_evidence());
        assert_eq!(meta.handle_count(), 2);
    }

    #[test]
    fn evidence_metadata_retrieval_hint() {
        let mut meta = EvidenceMetadata::empty();
        meta.set_retrieval_hint("fwc trace abc123");
        assert_eq!(meta.retrieval_hint.as_deref(), Some("fwc trace abc123"));
    }

    #[test]
    fn evidence_metadata_correlation_id_is_uuid() {
        let meta = EvidenceMetadata::empty();
        let id_str = meta.correlation_id.to_string();
        assert_eq!(id_str.len(), 36); // UUID v4 string format
    }

    #[test]
    fn resolution_carries_evidence() {
        let resolution = LiveTruthResolver::resolve_offline("test");
        // Default evidence is empty but has correlation ID
        assert!(!resolution.has_durable_evidence());
        assert!(!resolution.correlation_id().is_nil());
    }

    #[test]
    fn resolution_with_evidence_handle() {
        let resolution =
            LiveTruthResolver::resolve_host_direct("healthy", Duration::from_millis(5))
                .with_evidence_handle(EvidenceHandle::HostEndpoint {
                    path: "/health".into(),
                    query: None,
                })
                .with_evidence_handle(EvidenceHandle::AuditEvent {
                    zone_id: "z:private".into(),
                    seq: 1,
                    correlation_id: "c-1".into(),
                })
                .with_retrieval_hint("fwc trace --correlation c-1");

        assert!(resolution.has_durable_evidence());
        assert_eq!(resolution.evidence.handle_count(), 2);
        assert_eq!(
            resolution.evidence.retrieval_hint.as_deref(),
            Some("fwc trace --correlation c-1")
        );
    }

    #[test]
    fn resolution_correlation_id_matches_trace() {
        let resolution = LiveTruthResolver::resolve_offline("test");
        assert_eq!(resolution.correlation_id(), resolution.trace.correlation_id);
        assert_eq!(
            resolution.correlation_id(),
            resolution.evidence.correlation_id
        );
    }

    #[test]
    fn resolution_map_preserves_evidence() {
        let resolution = LiveTruthResolver::resolve_offline(42_u32).with_evidence_handle(
            EvidenceHandle::LocalArtifact {
                path: "manifest.toml".into(),
                artifact_type: ArtifactType::Manifest,
            },
        );
        let mapped = resolution.map(|v| v.to_string());
        assert_eq!(mapped.value, "42");
        assert_eq!(mapped.evidence.handle_count(), 1);
        assert!(!mapped.has_durable_evidence());
    }

    #[test]
    fn scenario_mesh_resolution_with_evidence() {
        let resolver = LiveTruthResolver::with_defaults();
        let result =
            resolver.resolve_sync(ResolutionStrategy::BestAvailable, |source| match source {
                KnowledgeState::MeshBacked => Some("distributed-health"),
                _ => None,
            });

        let resolution = result
            .unwrap()
            .with_evidence_handle(EvidenceHandle::MeshObject {
                object_id: "aabbccdd".into(),
                description: "ConnectorStateRoot for github".into(),
            })
            .with_evidence_handle(EvidenceHandle::AuditEvent {
                zone_id: "z:work".into(),
                seq: 100,
                correlation_id: "mesh-query-1".into(),
            })
            .with_retrieval_hint("fwc trace --object aabbccdd");

        assert_eq!(resolution.knowledge_state, KnowledgeState::MeshBacked);
        assert!(resolution.has_durable_evidence());
        assert_eq!(resolution.evidence.handle_count(), 2);
        assert!(!resolution.correlation_id().is_nil());
    }

    #[test]
    fn artifact_type_serde_roundtrip() {
        for at in [
            ArtifactType::Manifest,
            ArtifactType::RegistryCache,
            ArtifactType::HealthSnapshot,
            ArtifactType::HistoryLog,
            ArtifactType::Config,
        ] {
            let json = serde_json::to_string(&at).unwrap();
            let back: ArtifactType = serde_json::from_str(&json).unwrap();
            assert_eq!(at, back);
        }
    }

    // ── Acceptance tests: prove each knowledge mode (kpj16.3) ────────
    //
    // These tests exercise the resolver in each mode and assert that:
    // 1. The correct KnowledgeState is reported
    // 2. The DecisionTrace shows which branch fired
    // 3. Evidence handles can be attached for each mode
    // 4. Structured output can be serialized for audit/replay

    /// Helper: serialize a resolution to JSON for structured log verification.
    fn resolution_to_log<T: Serialize>(res: &TruthResolution<T>) -> serde_json::Value {
        serde_json::json!({
            "knowledge_state": res.knowledge_state.label(),
            "confidence": res.knowledge_state.confidence(),
            "is_live": res.knowledge_state.is_live(),
            "is_fallback": res.is_fallback(),
            "is_fresh": res.is_fresh(),
            "has_durable_evidence": res.has_durable_evidence(),
            "correlation_id": res.correlation_id().to_string(),
            "evidence_count": res.evidence.handle_count(),
            "retrieval_hint": res.evidence.retrieval_hint,
            "trace": {
                "strategy": format!("{}", res.trace.strategy),
                "selected_source": res.trace.selected_source.label(),
                "attempt_count": res.trace.attempts.len(),
                "reason": &res.trace.reason,
                "sources_tried": res.trace.attempts.iter()
                    .map(|a| serde_json::json!({
                        "source": a.source.label(),
                        "outcome": format!("{:?}", a.outcome),
                    }))
                    .collect::<Vec<_>>(),
            },
        })
    }

    #[test]
    fn acceptance_offline_mode() {
        // OFFLINE: connector discovered from local manifest, no host running
        let resolver = LiveTruthResolver::with_defaults();
        let result =
            resolver.resolve_sync(ResolutionStrategy::OfflineOnly, |source| match source {
                KnowledgeState::Offline => Some(serde_json::json!({
                    "connector_id": "github",
                    "version": "1.2.3",
                    "operations": ["issues.create", "issues.list"],
                })),
                _ => panic!("offline-only should not query other sources"),
            });

        let resolution = result
            .unwrap()
            .with_evidence_handle(EvidenceHandle::LocalArtifact {
                path: "connectors/github/manifest.toml".into(),
                artifact_type: ArtifactType::Manifest,
            });

        // Prove correct mode
        assert_eq!(resolution.knowledge_state, KnowledgeState::Offline);
        assert!(!resolution.knowledge_state.is_live());
        assert!((resolution.knowledge_state.confidence() - 0.4).abs() < f64::EPSILON);
        assert!(!resolution.is_fallback());

        // Prove trace shows offline branch
        assert_eq!(resolution.trace.attempts.len(), 1);
        assert_eq!(resolution.trace.attempts[0].source, KnowledgeState::Offline);
        assert_eq!(resolution.trace.attempts[0].outcome, SourceOutcome::Success);

        // Prove evidence is non-durable (local artifact)
        assert!(!resolution.has_durable_evidence());
        assert_eq!(resolution.evidence.handle_count(), 1);

        // Prove structured log is well-formed
        let log = resolution_to_log(&resolution);
        assert_eq!(log["knowledge_state"], "offline");
        assert_eq!(log["is_live"], false);
        assert_eq!(log["is_fallback"], false);
        assert_eq!(log["trace"]["strategy"], "offline-only");
    }

    #[test]
    fn acceptance_node_local_mode() {
        // NODE-LOCAL: cached health snapshot from last host query
        let resolver = LiveTruthResolver::with_defaults();
        let result =
            resolver.resolve_sync(ResolutionStrategy::NodeLocalOnly, |source| match source {
                KnowledgeState::NodeLocal => Some(serde_json::json!({
                    "connector_id": "slack",
                    "health_status": "healthy",
                    "cached_at": "2026-04-05T20:00:00Z",
                })),
                _ => None,
            });

        let resolution = result
            .unwrap()
            .with_evidence_handle(EvidenceHandle::LocalArtifact {
                path: "~/.fcp/cache/slack-health.json".into(),
                artifact_type: ArtifactType::HealthSnapshot,
            });

        assert_eq!(resolution.knowledge_state, KnowledgeState::NodeLocal);
        assert!(!resolution.knowledge_state.is_live());
        assert!((resolution.knowledge_state.confidence() - 0.6).abs() < f64::EPSILON);
        assert!(!resolution.is_fallback());

        let log = resolution_to_log(&resolution);
        assert_eq!(log["knowledge_state"], "node-local");
        assert_eq!(log["trace"]["attempt_count"], 1);
    }

    #[test]
    fn acceptance_host_backed_mode() {
        // HOST-BACKED: live query to host admin API
        let resolver = LiveTruthResolver::with_defaults();
        let result = resolver.resolve_sync(ResolutionStrategy::PreferHost, |source| match source {
            KnowledgeState::HostBacked => Some(serde_json::json!({
                "connector_id": "telegram",
                "runtime_status": "running",
                "pid": 12345,
                "uptime_seconds": 3600,
            })),
            _ => None,
        });

        let resolution = result
            .unwrap()
            .with_evidence_handle(EvidenceHandle::HostEndpoint {
                path: "/rpc/admin/status".into(),
                query: Some("connector=telegram".into()),
            });

        assert_eq!(resolution.knowledge_state, KnowledgeState::HostBacked);
        assert!(resolution.knowledge_state.is_live());
        assert!((resolution.knowledge_state.confidence() - 0.9).abs() < f64::EPSILON);
        assert!(!resolution.is_fallback());

        let log = resolution_to_log(&resolution);
        assert_eq!(log["knowledge_state"], "host-backed");
        assert_eq!(log["is_live"], true);
        assert_eq!(log["trace"]["selected_source"], "host-backed");
    }

    #[test]
    fn acceptance_mesh_backed_mode() {
        // MESH-BACKED: distributed state from mesh object store
        let resolver = LiveTruthResolver::with_defaults();
        let result =
            resolver.resolve_sync(ResolutionStrategy::BestAvailable, |source| match source {
                KnowledgeState::MeshBacked => Some(serde_json::json!({
                    "connector_id": "github",
                    "state_model": "singleton_writer",
                    "head_seq": 42,
                    "replicas": 3,
                })),
                KnowledgeState::HostBacked => Some(serde_json::json!({
                    "connector_id": "github",
                    "runtime_status": "running",
                })),
                _ => None,
            });

        let resolution = result
            .unwrap()
            .with_evidence_handle(EvidenceHandle::MeshObject {
                object_id: "aabb1122".into(),
                description: "ConnectorStateRoot for github".into(),
            })
            .with_evidence_handle(EvidenceHandle::AuditEvent {
                zone_id: "z:work".into(),
                seq: 42,
                correlation_id: "mesh-resolve-1".into(),
            })
            .with_retrieval_hint("fwc trace --object aabb1122");

        assert_eq!(resolution.knowledge_state, KnowledgeState::MeshBacked);
        assert!(resolution.knowledge_state.is_live());
        assert!((resolution.knowledge_state.confidence() - 1.0).abs() < f64::EPSILON);
        assert!(!resolution.is_fallback());

        // Mesh was tried first and succeeded — host was never queried
        assert_eq!(resolution.trace.attempts.len(), 1);
        assert_eq!(
            resolution.trace.attempts[0].source,
            KnowledgeState::MeshBacked
        );

        // Durable evidence attached
        assert!(resolution.has_durable_evidence());
        assert_eq!(resolution.evidence.handle_count(), 2);

        let log = resolution_to_log(&resolution);
        assert_eq!(log["knowledge_state"], "mesh-backed");
        assert_eq!(log["confidence"], 1.0);
        assert_eq!(log["has_durable_evidence"], true);
        assert_eq!(log["evidence_count"], 2);
    }

    #[test]
    fn acceptance_degraded_mode() {
        // DEGRADED: host returned partial data, mesh unavailable
        let resolver = LiveTruthResolver::with_defaults();
        let result =
            resolver.resolve_with_partials(ResolutionStrategy::PreferHost, |source| match source {
                KnowledgeState::HostBacked => QueryResult::<serde_json::Value>::Partial(
                    serde_json::json!({
                        "connector_id": "stripe",
                        "health_status": "unknown",
                        "note": "connector process timed out during health check",
                    }),
                    "health check timed out after 5s".into(),
                ),
                KnowledgeState::MeshBacked => {
                    QueryResult::Unavailable("mesh transport not configured".into())
                }
                _ => QueryResult::Unavailable("not available".into()),
            });

        let resolution = result
            .unwrap()
            .with_evidence_handle(EvidenceHandle::HostEndpoint {
                path: "/health".into(),
                query: Some("connector=stripe".into()),
            });

        assert_eq!(resolution.knowledge_state, KnowledgeState::Degraded);
        assert!(!resolution.knowledge_state.is_live());
        assert!((resolution.knowledge_state.confidence() - 0.3).abs() < f64::EPSILON);
        assert!(resolution.is_fallback());

        // Trace shows host was partial, mesh was unavailable
        let host_attempt = &resolution.trace.attempts[0];
        assert_eq!(host_attempt.source, KnowledgeState::HostBacked);
        assert_eq!(host_attempt.outcome, SourceOutcome::Partial);
        assert!(host_attempt.detail.as_ref().unwrap().contains("timed out"));

        let log = resolution_to_log(&resolution);
        assert_eq!(log["knowledge_state"], "degraded");
        assert_eq!(log["is_fallback"], true);
    }

    #[test]
    fn acceptance_fallback_derived_mode() {
        // FALLBACK: all preferred sources fail, falling back to offline
        let resolver = LiveTruthResolver::with_defaults();
        let mut source_log = Vec::new();
        let result = resolver.resolve_sync(ResolutionStrategy::BestAvailable, |source| {
            source_log.push((source, source == KnowledgeState::Offline));
            match source {
                KnowledgeState::Offline => Some(serde_json::json!({
                    "connector_id": "github",
                    "status": "manifest-declared",
                    "note": "no live data available",
                })),
                _ => None,
            }
        });

        let resolution = result
            .unwrap()
            .with_evidence_handle(EvidenceHandle::LocalArtifact {
                path: "connectors/github/manifest.toml".into(),
                artifact_type: ArtifactType::Manifest,
            });

        // Verify the resolver tried all 4 sources in BestAvailable order
        assert_eq!(source_log.len(), 4);
        assert_eq!(source_log[0].0, KnowledgeState::MeshBacked);
        assert_eq!(source_log[1].0, KnowledgeState::HostBacked);
        assert_eq!(source_log[2].0, KnowledgeState::NodeLocal);
        assert_eq!(source_log[3].0, KnowledgeState::Offline);

        // Offline succeeded after 3 failures = fallback
        assert_eq!(resolution.knowledge_state, KnowledgeState::Offline);
        assert!(resolution.is_fallback());

        // Trace has all 4 attempts
        assert_eq!(resolution.trace.attempts.len(), 4);
        assert_eq!(resolution.trace.failed_sources().len(), 3);
        assert_eq!(
            resolution.trace.successful_sources(),
            vec![KnowledgeState::Offline]
        );

        let log = resolution_to_log(&resolution);
        assert_eq!(log["is_fallback"], true);
        assert_eq!(log["trace"]["attempt_count"], 4);
    }

    #[test]
    fn acceptance_refusal_mode() {
        // REFUSAL: all sources fail, resolver returns error
        let resolver = LiveTruthResolver::with_defaults();
        let result: Result<TruthResolution<String>, _> = resolver.resolve_with_partials(
            ResolutionStrategy::BestAvailable,
            |source| match source {
                KnowledgeState::MeshBacked => QueryResult::Unavailable("mesh not joined".into()),
                KnowledgeState::HostBacked => QueryResult::Error("connection refused".into()),
                KnowledgeState::NodeLocal => QueryResult::NotConfigured,
                KnowledgeState::Offline => QueryResult::Unavailable("no manifests found".into()),
                _ => QueryResult::NotConfigured,
            },
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.strategy, ResolutionStrategy::BestAvailable);
        assert_eq!(err.attempts.len(), 4);

        // Each attempt has the right outcome
        assert_eq!(err.attempts[0].outcome, SourceOutcome::Unreachable);
        assert_eq!(err.attempts[1].outcome, SourceOutcome::Error);
        assert_eq!(err.attempts[2].outcome, SourceOutcome::NotConfigured);
        assert_eq!(err.attempts[3].outcome, SourceOutcome::Unreachable);

        // Error display is informative
        let display = format!("{err}");
        assert!(display.contains("best-available"));
        assert!(display.contains("4 sources tried"));
    }

    #[test]
    fn acceptance_structured_log_shape_is_stable() {
        // Prove that the structured log shape is stable for acceptance testing.
        // This prevents regressions in the log format that acceptance scripts
        // parse for automated verification.
        let resolver = LiveTruthResolver::with_defaults();
        let result = resolver
            .resolve_sync(ResolutionStrategy::PreferHost, |source| match source {
                KnowledgeState::HostBacked => Some("live"),
                _ => None,
            })
            .unwrap();

        let log = resolution_to_log(&result);

        // Assert all expected top-level keys exist
        assert!(log.get("knowledge_state").is_some());
        assert!(log.get("confidence").is_some());
        assert!(log.get("is_live").is_some());
        assert!(log.get("is_fallback").is_some());
        assert!(log.get("is_fresh").is_some());
        assert!(log.get("has_durable_evidence").is_some());
        assert!(log.get("correlation_id").is_some());
        assert!(log.get("evidence_count").is_some());
        assert!(log.get("trace").is_some());

        // Assert trace sub-keys
        let trace = &log["trace"];
        assert!(trace.get("strategy").is_some());
        assert!(trace.get("selected_source").is_some());
        assert!(trace.get("attempt_count").is_some());
        assert!(trace.get("reason").is_some());
        assert!(trace.get("sources_tried").is_some());

        // Assert sources_tried entries have expected shape
        let sources = trace["sources_tried"].as_array().unwrap();
        assert!(!sources.is_empty());
        assert!(sources[0].get("source").is_some());
        assert!(sources[0].get("outcome").is_some());
    }

    #[test]
    fn acceptance_intent_provenance_backward_compat_all_modes() {
        // Prove backward compatibility with IntentProvenance for all modes
        let cases: Vec<(KnowledgeState, IntentProvenance)> = vec![
            (KnowledgeState::MeshBacked, IntentProvenance::MeshBacked),
            (KnowledgeState::HostBacked, IntentProvenance::HostBacked),
            (KnowledgeState::NodeLocal, IntentProvenance::Offline),
            (KnowledgeState::Offline, IntentProvenance::Offline),
            (KnowledgeState::Degraded, IntentProvenance::Degraded),
            (KnowledgeState::FallbackDerived, IntentProvenance::Degraded),
        ];

        for (ks, expected_ip) in cases {
            assert_eq!(
                ks.to_intent_provenance(),
                expected_ip,
                "{} should map to {:?}",
                ks.label(),
                expected_ip
            );
        }
    }

    // ── Operator evidence-lookup model (o8umn.1) ──────────────────────

    #[test]
    fn operator_command_drill_down_hint() {
        let id = Uuid::new_v4();
        let hint = OperatorCommand::Doctor.drill_down_hint(&id);
        assert!(hint.contains("fwc trace"));
        assert!(hint.contains(&id.to_string()));
        assert!(hint.contains("doctor"));
    }

    #[test]
    fn operator_evidence_lookup_from_resolution() {
        let resolution =
            LiveTruthResolver::resolve_host_direct("healthy", Duration::from_millis(10))
                .with_evidence_handle(EvidenceHandle::HostEndpoint {
                    path: "/health".into(),
                    query: None,
                });

        let lookup = OperatorEvidenceLookup::from_resolution(
            OperatorCommand::Health,
            Some("github".into()),
            &resolution,
        );

        assert_eq!(lookup.command, OperatorCommand::Health);
        assert_eq!(lookup.connector_id.as_deref(), Some("github"));
        assert_eq!(lookup.knowledge_state, KnowledgeState::HostBacked);
        assert_eq!(lookup.correlation_id, resolution.correlation_id());
        assert_eq!(lookup.evidence_handles.len(), 1);
        assert!(!lookup.has_durable_evidence());
        assert!(lookup.retrieval_command.contains("health"));
    }

    #[test]
    fn operator_evidence_lookup_drill_down_actions() {
        let resolution = LiveTruthResolver::resolve_offline("test");
        let mut lookup = OperatorEvidenceLookup::from_resolution(
            OperatorCommand::Doctor,
            Some("slack".into()),
            &resolution,
        );

        lookup.add_drill_down(
            "View connector manifest",
            "fwc show slack --offline",
            "Check declared capabilities and version",
        );
        lookup.add_drill_down(
            "Check auth status",
            "fwc auth verify slack",
            "Verify credential validity",
        );

        assert_eq!(lookup.drill_down_count(), 2);
        assert_eq!(lookup.drill_down[0].label, "View connector manifest");
        assert_eq!(lookup.drill_down[1].command, "fwc auth verify slack");
    }

    #[test]
    fn operator_evidence_lookup_structured_log() {
        let resolution =
            LiveTruthResolver::resolve_host_direct("running", Duration::from_millis(5))
                .with_evidence_handle(EvidenceHandle::AuditEvent {
                    zone_id: "z:work".into(),
                    seq: 10,
                    correlation_id: "c-10".into(),
                });

        let mut lookup = OperatorEvidenceLookup::from_resolution(
            OperatorCommand::Status,
            Some("telegram".into()),
            &resolution,
        );
        lookup.add_drill_down(
            "View audit log",
            "fwc audit --zone z:work",
            "Check recent operations",
        );

        let log = lookup.to_structured_log();

        // Assert all required fields are present
        assert_eq!(log["command"], "status");
        assert_eq!(log["connector_id"], "telegram");
        assert_eq!(log["knowledge_state"], "host-backed");
        assert_eq!(log["is_live"], true);
        assert!(log["correlation_id"].is_string());
        assert_eq!(log["evidence_count"], 1);
        assert_eq!(log["has_durable_evidence"], true);
        assert!(
            log["retrieval_command"]
                .as_str()
                .unwrap()
                .contains("status")
        );

        // Drill-down entries are present
        let drill = log["drill_down"].as_array().unwrap();
        assert_eq!(drill.len(), 1);
        assert_eq!(drill[0]["label"], "View audit log");
    }

    #[test]
    fn operator_evidence_all_commands_have_drill_down_hints() {
        let id = Uuid::new_v4();
        for cmd in [
            OperatorCommand::Doctor,
            OperatorCommand::Preflight,
            OperatorCommand::Show,
            OperatorCommand::Health,
            OperatorCommand::Explain,
            OperatorCommand::Status,
        ] {
            let hint = cmd.drill_down_hint(&id);
            assert!(
                hint.contains("fwc trace"),
                "drill_down_hint for {:?} should contain 'fwc trace'",
                cmd
            );
            assert!(
                hint.contains(&id.to_string()),
                "drill_down_hint for {:?} should contain correlation ID",
                cmd
            );
        }
    }

    #[test]
    fn operator_evidence_consistent_across_commands() {
        // Prove the model is consistent: same resolution + different commands
        // produce structurally identical outputs (just different command tags).
        let resolution = LiveTruthResolver::resolve_offline(serde_json::json!({"status": "ok"}));

        let commands = [
            OperatorCommand::Doctor,
            OperatorCommand::Show,
            OperatorCommand::Health,
        ];

        let lookups: Vec<_> = commands
            .iter()
            .map(|cmd| {
                OperatorEvidenceLookup::from_resolution(*cmd, Some("github".into()), &resolution)
            })
            .collect();

        // All share the same knowledge state and evidence structure
        for lookup in &lookups {
            assert_eq!(lookup.knowledge_state, KnowledgeState::Offline);
            assert_eq!(lookup.connector_id.as_deref(), Some("github"));
            assert_eq!(lookup.evidence_handles.len(), 0);
        }

        // But they have different command tags
        assert_eq!(lookups[0].command, OperatorCommand::Doctor);
        assert_eq!(lookups[1].command, OperatorCommand::Show);
        assert_eq!(lookups[2].command, OperatorCommand::Health);

        // And different retrieval commands
        assert!(lookups[0].retrieval_command.contains("doctor"));
        assert!(lookups[1].retrieval_command.contains("show"));
        assert!(lookups[2].retrieval_command.contains("health"));
    }

    #[test]
    fn operator_evidence_serde_roundtrip() {
        let resolution = LiveTruthResolver::resolve_offline("data");
        let mut lookup = OperatorEvidenceLookup::from_resolution(
            OperatorCommand::Explain,
            Some("stripe".into()),
            &resolution,
        );
        lookup.add_drill_down("Check logs", "fwc trace abc", "Debug");

        let json = serde_json::to_string(&lookup).unwrap();
        let back: OperatorEvidenceLookup = serde_json::from_str(&json).unwrap();
        assert_eq!(back.command, OperatorCommand::Explain);
        assert_eq!(back.connector_id.as_deref(), Some("stripe"));
        assert_eq!(back.drill_down.len(), 1);
    }

    // ── Remediation-aware output (o8umn.2) ────────────────────────────

    #[test]
    fn remediation_severity_ordering() {
        assert!(RemediationSeverity::Critical > RemediationSeverity::Error);
        assert!(RemediationSeverity::Error > RemediationSeverity::Warning);
        assert!(RemediationSeverity::Warning > RemediationSeverity::Info);
    }

    #[test]
    fn remediation_output_no_issues() {
        let resolution =
            LiveTruthResolver::resolve_host_direct("healthy", Duration::from_millis(5));
        let lookup = OperatorEvidenceLookup::from_resolution(
            OperatorCommand::Health,
            Some("github".into()),
            &resolution,
        );
        let mut output = RemediationOutput::new(lookup, "github: healthy");
        output.add_finding(RemediationFinding {
            summary: "All operations responding normally".into(),
            detail: None,
            severity: RemediationSeverity::Info,
            evidence: Some(EvidenceHandle::HostEndpoint {
                path: "/health".into(),
                query: Some("connector=github".into()),
            }),
            next_actions: vec![],
        });

        assert!(!output.has_issues);
        assert_eq!(output.severity_counts.info, 1);
        assert_eq!(output.severity_counts.total(), 1);
        assert_eq!(output.finding_count(), 1);
    }

    #[test]
    fn remediation_output_with_issues() {
        let resolution =
            LiveTruthResolver::resolve_host_direct("degraded", Duration::from_millis(10));
        let lookup = OperatorEvidenceLookup::from_resolution(
            OperatorCommand::Doctor,
            Some("slack".into()),
            &resolution,
        );
        let mut output = RemediationOutput::new(lookup, "slack: auth expired");

        output.add_finding(RemediationFinding {
            summary: "OAuth token expired 3 days ago".into(),
            detail: Some("Token expired at 2026-04-02T00:00:00Z".into()),
            severity: RemediationSeverity::Error,
            evidence: Some(EvidenceHandle::LocalArtifact {
                path: "~/.fcp/credentials/slack.json".into(),
                artifact_type: ArtifactType::Config,
            }),
            next_actions: vec![DrillDownAction {
                label: "Re-authenticate".into(),
                command: "fwc auth refresh slack".into(),
                rationale: "Obtain a fresh OAuth token".into(),
            }],
        });

        output.add_finding(RemediationFinding {
            summary: "Rate limit approaching threshold".into(),
            detail: None,
            severity: RemediationSeverity::Warning,
            evidence: None,
            next_actions: vec![],
        });

        assert!(output.has_issues);
        assert_eq!(output.severity_counts.error, 1);
        assert_eq!(output.severity_counts.warning, 1);
        assert_eq!(output.severity_counts.total(), 2);
        assert_eq!(output.finding_count(), 2);

        let worst = output.worst_finding().unwrap();
        assert_eq!(worst.severity, RemediationSeverity::Error);
        assert!(worst.summary.contains("OAuth"));
    }

    #[test]
    fn remediation_output_sort_by_severity() {
        let resolution = LiveTruthResolver::resolve_offline("test");
        let lookup = OperatorEvidenceLookup::from_resolution(
            OperatorCommand::Preflight,
            Some("stripe".into()),
            &resolution,
        );
        let mut output = RemediationOutput::new(lookup, "stripe: issues found");

        output.add_finding(RemediationFinding {
            summary: "Info note".into(),
            detail: None,
            severity: RemediationSeverity::Info,
            evidence: None,
            next_actions: vec![],
        });
        output.add_finding(RemediationFinding {
            summary: "Critical issue".into(),
            detail: None,
            severity: RemediationSeverity::Critical,
            evidence: None,
            next_actions: vec![],
        });
        output.add_finding(RemediationFinding {
            summary: "Warning".into(),
            detail: None,
            severity: RemediationSeverity::Warning,
            evidence: None,
            next_actions: vec![],
        });

        output.sort_by_severity();
        assert_eq!(output.findings[0].severity, RemediationSeverity::Critical);
        assert_eq!(output.findings[1].severity, RemediationSeverity::Warning);
        assert_eq!(output.findings[2].severity, RemediationSeverity::Info);
    }

    #[test]
    fn remediation_output_structured_log() {
        let resolution =
            LiveTruthResolver::resolve_host_direct("running", Duration::from_millis(5));
        let lookup = OperatorEvidenceLookup::from_resolution(
            OperatorCommand::Status,
            Some("telegram".into()),
            &resolution,
        );
        let mut output = RemediationOutput::new(lookup, "telegram: running");
        output.add_finding(RemediationFinding {
            summary: "High latency detected".into(),
            detail: Some("p99 latency 2.3s (threshold 1s)".into()),
            severity: RemediationSeverity::Warning,
            evidence: Some(EvidenceHandle::HostEndpoint {
                path: "/rpc/admin/metrics".into(),
                query: Some("connector=telegram".into()),
            }),
            next_actions: vec![DrillDownAction {
                label: "Check network".into(),
                command: "fwc net telegram".into(),
                rationale: "Diagnose network path".into(),
            }],
        });

        let log = output.to_structured_log();
        assert_eq!(log["command"], "status");
        assert_eq!(log["connector_id"], "telegram");
        assert_eq!(log["summary"], "telegram: running");
        assert_eq!(log["has_issues"], true);
        assert_eq!(log["severity_counts"]["warning"], 1);

        let findings = log["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["severity"], "warning");
        assert_eq!(findings[0]["has_evidence"], true);
        assert_eq!(findings[0]["next_actions"], 1);
    }

    #[test]
    fn remediation_output_serde_roundtrip() {
        let resolution = LiveTruthResolver::resolve_offline("data");
        let lookup = OperatorEvidenceLookup::from_resolution(
            OperatorCommand::Explain,
            Some("github".into()),
            &resolution,
        );
        let mut output = RemediationOutput::new(lookup, "github: explained");
        output.add_finding(RemediationFinding {
            summary: "Using offline artifacts".into(),
            detail: None,
            severity: RemediationSeverity::Info,
            evidence: None,
            next_actions: vec![],
        });

        let json = serde_json::to_string(&output).unwrap();
        let back: RemediationOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(back.summary, "github: explained");
        assert_eq!(back.findings.len(), 1);
        assert_eq!(back.severity_counts.info, 1);
    }

    #[test]
    fn remediation_scenario_doctor_with_evidence() {
        // Full scenario: doctor command finds auth expired and suggests fix
        let resolver = LiveTruthResolver::with_defaults();
        let result = resolver.resolve_sync(ResolutionStrategy::PreferHost, |source| match source {
            KnowledgeState::HostBacked => Some(serde_json::json!({
                "connector_id": "slack",
                "health": "degraded",
                "auth_status": "expired",
                "last_success": "2026-04-01T12:00:00Z",
            })),
            _ => None,
        });

        let resolution = result
            .unwrap()
            .with_evidence_handle(EvidenceHandle::HostEndpoint {
                path: "/health".into(),
                query: Some("connector=slack".into()),
            });

        let lookup = OperatorEvidenceLookup::from_resolution(
            OperatorCommand::Doctor,
            Some("slack".into()),
            &resolution,
        );

        let mut output = RemediationOutput::new(lookup, "slack: auth expired, needs refresh");
        output.add_finding(RemediationFinding {
            summary: "OAuth token expired".into(),
            detail: Some("Last successful auth: 2026-04-01T12:00:00Z".into()),
            severity: RemediationSeverity::Error,
            evidence: Some(EvidenceHandle::HostEndpoint {
                path: "/health".into(),
                query: Some("connector=slack&field=auth_status".into()),
            }),
            next_actions: vec![
                DrillDownAction {
                    label: "Refresh OAuth token".into(),
                    command: "fwc auth refresh slack".into(),
                    rationale: "Re-authenticate with Slack OAuth".into(),
                },
                DrillDownAction {
                    label: "View credential details".into(),
                    command: "fwc auth verify slack".into(),
                    rationale: "Check stored credential metadata".into(),
                },
            ],
        });

        // Verify the complete chain
        assert!(output.has_issues);
        assert_eq!(output.evidence_lookup.command, OperatorCommand::Doctor);
        assert_eq!(
            output.evidence_lookup.knowledge_state,
            KnowledgeState::HostBacked
        );
        assert!(!output.evidence_lookup.correlation_id.is_nil());

        let worst = output.worst_finding().unwrap();
        assert_eq!(worst.severity, RemediationSeverity::Error);
        assert_eq!(worst.next_actions.len(), 2);
        assert_eq!(worst.next_actions[0].command, "fwc auth refresh slack");

        let log = output.to_structured_log();
        assert_eq!(log["knowledge_state"], "host-backed");
        assert_eq!(log["has_issues"], true);
    }

    // ── Snapshot/transcript proof (o8umn.3) ───────────────────────────
    //
    // These tests freeze the JSON shapes of operator evidence outputs
    // so that later doc/proof beads and acceptance scripts can rely on
    // a stable structure. Each test captures a complete "transcript" —
    // the full JSON snapshot of a RemediationOutput for a specific
    // operator journey.

    /// Helper: build a fixed-UUID resolution for deterministic snapshots.
    fn deterministic_resolution(state: KnowledgeState) -> TruthResolution<serde_json::Value> {
        let fixed_uuid = Uuid::from_bytes([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef,
        ]);
        let freshness = TruthFreshness::now(Duration::from_secs(30), Duration::from_millis(5));
        let trace = DecisionTrace {
            attempts: vec![SourceAttempt {
                source: state,
                outcome: SourceOutcome::Success,
                elapsed: Duration::from_millis(5),
                detail: None,
            }],
            selected_source: state,
            strategy: ResolutionStrategy::PreferHost,
            reason: format!("{} returned a complete answer", state.label()),
            used_fallback: false,
            correlation_id: fixed_uuid,
        };
        let evidence = EvidenceMetadata::with_correlation_id(fixed_uuid);
        TruthResolution {
            value: serde_json::json!({"status": "test"}),
            knowledge_state: state,
            freshness,
            trace,
            evidence,
        }
    }

    #[test]
    fn snapshot_healthy_doctor_journey() {
        let resolution = deterministic_resolution(KnowledgeState::HostBacked);
        let lookup = OperatorEvidenceLookup::from_resolution(
            OperatorCommand::Doctor,
            Some("github".into()),
            &resolution,
        );
        let mut output = RemediationOutput::new(lookup, "github: all checks passed");
        output.add_finding(RemediationFinding {
            summary: "Authentication valid".into(),
            detail: Some("OAuth token expires in 29 days".into()),
            severity: RemediationSeverity::Info,
            evidence: Some(EvidenceHandle::HostEndpoint {
                path: "/health".into(),
                query: Some("connector=github".into()),
            }),
            next_actions: vec![],
        });
        output.add_finding(RemediationFinding {
            summary: "Rate limits nominal".into(),
            detail: Some("4,200/5,000 requests remaining (84%)".into()),
            severity: RemediationSeverity::Info,
            evidence: None,
            next_actions: vec![],
        });

        let log = output.to_structured_log();

        // Snapshot assertions: frozen shape contract
        assert_eq!(log["command"], "doctor");
        assert_eq!(log["connector_id"], "github");
        assert!(!log["has_issues"].as_bool().unwrap());
        assert_eq!(log["severity_counts"]["critical"], 0);
        assert_eq!(log["severity_counts"]["error"], 0);
        assert_eq!(log["severity_counts"]["warning"], 0);
        assert_eq!(log["severity_counts"]["info"], 2);
        let findings = log["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0]["severity"], "info");
        assert_eq!(findings[1]["severity"], "info");
    }

    #[test]
    fn snapshot_denied_preflight_journey() {
        let resolution = deterministic_resolution(KnowledgeState::HostBacked);
        let lookup = OperatorEvidenceLookup::from_resolution(
            OperatorCommand::Preflight,
            Some("stripe".into()),
            &resolution,
        );
        let mut output = RemediationOutput::new(lookup, "stripe: preflight DENIED");
        output.add_finding(RemediationFinding {
            summary: "Capability token missing for stripe.charges.create".into(),
            detail: Some("Operation requires z:private capability grant".into()),
            severity: RemediationSeverity::Critical,
            evidence: Some(EvidenceHandle::AuditEvent {
                zone_id: "z:work".into(),
                seq: 99,
                correlation_id: "preflight-1".into(),
            }),
            next_actions: vec![DrillDownAction {
                label: "Request capability grant".into(),
                command: "fwc capabilities request stripe charges.create --zone z:private".into(),
                rationale: "Obtain the required capability token from zone owner".into(),
            }],
        });
        output.add_finding(RemediationFinding {
            summary: "Operation classified as Risky".into(),
            detail: Some("stripe.charges.create has SafetyTier::Risky — requires approval".into()),
            severity: RemediationSeverity::Warning,
            evidence: None,
            next_actions: vec![DrillDownAction {
                label: "Review safety classification".into(),
                command: "fwc ops stripe charges.create --offline".into(),
                rationale: "Understand why this operation requires elevated approval".into(),
            }],
        });

        let log = output.to_structured_log();

        assert_eq!(log["command"], "preflight");
        assert!(log["has_issues"].as_bool().unwrap());
        assert_eq!(log["severity_counts"]["critical"], 1);
        assert_eq!(log["severity_counts"]["warning"], 1);
        let findings = log["findings"].as_array().unwrap();
        assert_eq!(findings[0]["has_evidence"], true);
        assert_eq!(findings[0]["next_actions"], 1);
        assert_eq!(findings[1]["next_actions"], 1);
    }

    #[test]
    fn snapshot_degraded_health_journey() {
        let resolution = deterministic_resolution(KnowledgeState::Degraded);
        let lookup = OperatorEvidenceLookup::from_resolution(
            OperatorCommand::Health,
            None, // fleet-wide
            &resolution,
        );
        let mut output = RemediationOutput::new(lookup, "fleet: 2/5 connectors degraded");
        output.add_finding(RemediationFinding {
            summary: "slack: high latency (p99 = 3.2s)".into(),
            detail: None,
            severity: RemediationSeverity::Warning,
            evidence: Some(EvidenceHandle::HostEndpoint {
                path: "/health".into(),
                query: Some("connector=slack".into()),
            }),
            next_actions: vec![DrillDownAction {
                label: "Check Slack API status".into(),
                command: "fwc doctor slack".into(),
                rationale: "Run full diagnostic on Slack connector".into(),
            }],
        });
        output.add_finding(RemediationFinding {
            summary: "telegram: connection refused".into(),
            detail: Some("Last successful connection: 2026-04-05T19:30:00Z".into()),
            severity: RemediationSeverity::Error,
            evidence: None,
            next_actions: vec![DrillDownAction {
                label: "Restart connector".into(),
                command: "fwc lifecycle --action restart telegram".into(),
                rationale: "Attempt to re-establish connection".into(),
            }],
        });

        output.sort_by_severity();
        let log = output.to_structured_log();

        assert_eq!(log["command"], "health");
        assert!(log["connector_id"].is_null()); // fleet-wide
        assert_eq!(log["knowledge_state"], "degraded");
        assert!(log["has_issues"].as_bool().unwrap());
        assert_eq!(log["severity_counts"]["error"], 1);
        assert_eq!(log["severity_counts"]["warning"], 1);
    }

    #[test]
    fn snapshot_drill_down_explain_journey() {
        let resolution = deterministic_resolution(KnowledgeState::MeshBacked);
        let mut lookup = OperatorEvidenceLookup::from_resolution(
            OperatorCommand::Explain,
            Some("github".into()),
            &resolution,
        );
        lookup.add_drill_down(
            "View mesh object",
            "fwc trace --object aabb1122",
            "Inspect the ConnectorStateRoot",
        );
        lookup.add_drill_down(
            "View audit chain",
            "fwc audit --zone z:work --last 10",
            "Check recent operations",
        );

        let mut output = RemediationOutput::new(lookup, "github: explain mesh state");
        output.add_finding(RemediationFinding {
            summary: "State sourced from mesh (3 replicas)".into(),
            detail: Some("ConnectorStateRoot seq=42, 3/3 nodes confirmed".into()),
            severity: RemediationSeverity::Info,
            evidence: Some(EvidenceHandle::MeshObject {
                object_id: "aabb1122".into(),
                description: "ConnectorStateRoot for github".into(),
            }),
            next_actions: vec![],
        });

        let log = output.to_structured_log();

        assert_eq!(log["command"], "explain");
        assert_eq!(log["knowledge_state"], "mesh-backed");
        assert!(!log["has_issues"].as_bool().unwrap());
        let findings = log["findings"].as_array().unwrap();
        assert_eq!(findings[0]["has_evidence"], true);
    }

    #[test]
    fn snapshot_all_journeys_share_stable_shape() {
        // Verify that all journey snapshots share the same top-level keys.
        let commands = [
            OperatorCommand::Doctor,
            OperatorCommand::Preflight,
            OperatorCommand::Show,
            OperatorCommand::Health,
            OperatorCommand::Explain,
            OperatorCommand::Status,
        ];

        let required_keys = [
            "command",
            "connector_id",
            "summary",
            "knowledge_state",
            "has_issues",
            "severity_counts",
            "correlation_id",
            "retrieval_command",
            "findings",
        ];

        for cmd in commands {
            let resolution = deterministic_resolution(KnowledgeState::HostBacked);
            let lookup =
                OperatorEvidenceLookup::from_resolution(cmd, Some("test".into()), &resolution);
            let output = RemediationOutput::new(lookup, "test");
            let log = output.to_structured_log();

            for key in &required_keys {
                assert!(
                    log.get(key).is_some(),
                    "Missing key '{}' in {:?} output",
                    key,
                    cmd
                );
            }
        }
    }
}
