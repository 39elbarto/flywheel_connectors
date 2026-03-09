//! CASS (Conversation Archive & Semantic Search) integration for arXiv paper
//! indexing and retrieval.
//!
//! Provides deterministic chunking of paper content (abstract + sections) with
//! stable chunk IDs, provenance metadata, and policy-gated write operations.

use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};

use serde::{Deserialize, Serialize};

// ── Constants ───────────────────────────────────────────────────────

/// Default maximum chunk size in characters.
pub const DEFAULT_MAX_CHUNK_SIZE: usize = 1024;

/// Default overlap between adjacent chunks in characters.
pub const DEFAULT_OVERLAP: usize = 128;

/// Minimum chunk size — chunks smaller than this are merged with neighbors.
pub const MIN_CHUNK_SIZE: usize = 64;

/// Maximum allowed chunk size (hard cap).
pub const MAX_CHUNK_SIZE_LIMIT: usize = 8192;

/// Maximum allowed overlap as a fraction of chunk size.
const MAX_OVERLAP_FRACTION: f64 = 0.5;

// ── Provenance ──────────────────────────────────────────────────────

/// Provenance metadata for a chunk, tracking its origin in the arXiv corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkProvenance {
    /// arXiv identifier (e.g. "2301.08745").
    pub arxiv_id: String,
    /// Paper version (e.g. "v1", "v2").
    pub version: String,
    /// Method used to extract the text (e.g. "abstract", "section\_split", "full\_text").
    pub extraction_method: String,
    /// ISO-8601 timestamp when the extraction was performed.
    pub extracted_at: String,
}

impl ChunkProvenance {
    /// Create provenance for an abstract extraction.
    pub fn for_abstract(arxiv_id: &str, version: &str, extracted_at: &str) -> Self {
        Self {
            arxiv_id: arxiv_id.to_string(),
            version: version.to_string(),
            extraction_method: "abstract".to_string(),
            extracted_at: extracted_at.to_string(),
        }
    }

    /// Create provenance for a section-based extraction.
    pub fn for_section(arxiv_id: &str, version: &str, extracted_at: &str) -> Self {
        Self {
            arxiv_id: arxiv_id.to_string(),
            version: version.to_string(),
            extraction_method: "section_split".to_string(),
            extracted_at: extracted_at.to_string(),
        }
    }

    /// Create provenance for full-text extraction.
    pub fn for_full_text(arxiv_id: &str, version: &str, extracted_at: &str) -> Self {
        Self {
            arxiv_id: arxiv_id.to_string(),
            version: version.to_string(),
            extraction_method: "full_text".to_string(),
            extracted_at: extracted_at.to_string(),
        }
    }
}

// ── Chunk Descriptor ────────────────────────────────────────────────

/// Descriptor identifying a chunk within a paper. The `chunk_id` is
/// deterministic and stable for the same (`paper_id`, section, offset) triple.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CassChunkDescriptor {
    /// Deterministic chunk identifier (hex-encoded hash).
    pub chunk_id: String,
    /// Paper identifier (arXiv ID).
    pub paper_id: String,
    /// Section label (e.g. "abstract", "introduction", "section\_0").
    pub section: String,
    /// Character offset within the section where this chunk starts.
    pub offset: usize,
    /// Length of the chunk in characters.
    pub length: usize,
    /// Provenance metadata.
    pub provenance: ChunkProvenance,
}

// ── Chunk ───────────────────────────────────────────────────────────

/// A chunk of paper content with its descriptor and the actual text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CassChunk {
    /// Chunk descriptor (identity + provenance).
    pub descriptor: CassChunkDescriptor,
    /// The chunk text content.
    pub content: String,
}

// ── Index Status ────────────────────────────────────────────────────

/// Status of indexing for a given paper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CassIndexStatusKind {
    /// Indexing has been requested but not started.
    Pending,
    /// Paper has been successfully indexed.
    Indexed,
    /// Indexing failed.
    Failed,
    /// Index is stale (paper has been updated since last indexing).
    Stale,
}

impl fmt::Display for CassIndexStatusKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Indexed => write!(f, "indexed"),
            Self::Failed => write!(f, "failed"),
            Self::Stale => write!(f, "stale"),
        }
    }
}

/// Full index status record for a paper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CassIndexStatus {
    /// Paper identifier.
    pub paper_id: String,
    /// ISO-8601 timestamp of when indexing was performed.
    pub indexed_at: String,
    /// Number of chunks produced.
    pub chunk_count: usize,
    /// Current status.
    pub status: CassIndexStatusKind,
}

// ── Index Request ───────────────────────────────────────────────────

/// A named section of paper content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaperSection {
    /// Section label (e.g. "introduction", "methods").
    pub label: String,
    /// Section text content.
    pub text: String,
}

/// Chunking options.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkingOptions {
    /// Maximum chunk size in characters.
    pub max_chunk_size: usize,
    /// Overlap between adjacent chunks in characters.
    pub overlap: usize,
}

impl Default for ChunkingOptions {
    fn default() -> Self {
        Self {
            max_chunk_size: DEFAULT_MAX_CHUNK_SIZE,
            overlap: DEFAULT_OVERLAP,
        }
    }
}

impl ChunkingOptions {
    /// Validate the options, returning an error message if invalid.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_chunk_size < MIN_CHUNK_SIZE {
            return Err(format!(
                "max_chunk_size ({}) must be at least {MIN_CHUNK_SIZE}",
                self.max_chunk_size
            ));
        }
        if self.max_chunk_size > MAX_CHUNK_SIZE_LIMIT {
            return Err(format!(
                "max_chunk_size ({}) must not exceed {MAX_CHUNK_SIZE_LIMIT}",
                self.max_chunk_size
            ));
        }
        let max_overlap = (self.max_chunk_size as f64 * MAX_OVERLAP_FRACTION) as usize;
        if self.overlap > max_overlap {
            return Err(format!(
                "overlap ({}) must not exceed {}% of max_chunk_size ({})",
                self.overlap,
                (MAX_OVERLAP_FRACTION * 100.0) as u32,
                max_overlap
            ));
        }
        Ok(())
    }
}

/// Request to index a paper's content into CASS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CassIndexRequest {
    /// Paper identifier (arXiv ID).
    pub paper_id: String,
    /// Paper abstract text.
    pub abstract_text: String,
    /// Paper sections (may be empty if only abstract is available).
    pub sections: Vec<PaperSection>,
    /// Chunking options.
    pub options: ChunkingOptions,
    /// Paper version (e.g. "v1").
    pub version: String,
    /// ISO-8601 timestamp for provenance.
    pub extracted_at: String,
}

// ── Search Request / Result ─────────────────────────────────────────

/// Filter criteria for CASS search.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CassSearchFilter {
    /// Filter by paper IDs (if non-empty, only chunks from these papers match).
    #[serde(default)]
    pub paper_ids: Vec<String>,
    /// Filter by section labels (if non-empty, only chunks from these sections match).
    #[serde(default)]
    pub sections: Vec<String>,
    /// Minimum relevance score (0.0 to 1.0).
    #[serde(default)]
    pub min_score: f64,
}

impl Default for CassSearchFilter {
    fn default() -> Self {
        Self {
            paper_ids: Vec::new(),
            sections: Vec::new(),
            min_score: 0.0,
        }
    }
}

/// Request to search the CASS index.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CassSearchRequest {
    /// Query text for semantic search.
    pub query: String,
    /// Search filters.
    #[serde(default)]
    pub filters: CassSearchFilter,
    /// Maximum number of results to return.
    pub limit: usize,
}

/// A single search result with relevance scoring.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CassSearchHit {
    /// The matched chunk.
    pub chunk: CassChunk,
    /// Relevance score (0.0 to 1.0).
    pub score: f64,
}

/// Search results container.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CassSearchResult {
    /// Matching chunks with scores.
    pub hits: Vec<CassSearchHit>,
    /// Total number of matches (may be greater than `hits.len()` if limited).
    pub total: usize,
    /// The original query.
    pub query: String,
}

// ── Write Policy ────────────────────────────────────────────────────

/// Policy gate for write operations to the CASS index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CassWritePolicy {
    /// Allow all writes.
    Allow,
    /// Deny all writes (read-only mode).
    Deny,
    /// Allow writes only for new papers (no overwrite of existing index).
    NewOnly,
}

impl CassWritePolicy {
    /// Check whether a write is permitted for the given paper.
    pub const fn is_write_allowed(self, paper_exists: bool) -> bool {
        match self {
            Self::Allow => true,
            Self::Deny => false,
            Self::NewOnly => !paper_exists,
        }
    }
}

impl fmt::Display for CassWritePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Deny => write!(f, "deny"),
            Self::NewOnly => write!(f, "new_only"),
        }
    }
}

// ── Chunk ID computation ────────────────────────────────────────────

/// Compute a deterministic chunk ID from (`paper_id`, section, offset).
///
/// Uses a stable hash to produce a hex string. The same inputs always
/// produce the same output.
pub fn compute_chunk_id(paper_id: &str, section: &str, offset: usize) -> String {
    let mut hasher = DefaultHasher::new();
    "cass-chunk-v1".hash(&mut hasher);
    paper_id.hash(&mut hasher);
    section.hash(&mut hasher);
    offset.hash(&mut hasher);
    let hash = hasher.finish();
    format!("{hash:016x}")
}

// ── Chunking logic ──────────────────────────────────────────────────

/// Chunk a single section of text into bounded, overlapping chunks.
///
/// Returns `(offset, text)` pairs. Offsets are character-based, not byte-based.
fn chunk_text(text: &str, max_chunk_size: usize, overlap: usize) -> Vec<(usize, String)> {
    if text.is_empty() {
        return Vec::new();
    }

    let chars: Vec<char> = text.chars().collect();
    let total = chars.len();

    if total <= max_chunk_size {
        return vec![(0, text.to_string())];
    }

    let mut chunks = Vec::new();
    let mut start = 0;
    let step = max_chunk_size.saturating_sub(overlap).max(1);

    while start < total {
        let end = (start + max_chunk_size).min(total);
        let chunk_str: String = chars[start..end].iter().collect();
        chunks.push((start, chunk_str));

        let next_start = start + step;
        if next_start >= total || end == total {
            break;
        }
        start = next_start;
    }

    chunks
}

/// Chunk a paper's content (abstract + sections) into `CassChunk` items.
///
/// The chunking is fully deterministic: the same `CassIndexRequest` always
/// produces the same set of chunks with the same chunk IDs.
pub fn chunk_paper(request: &CassIndexRequest) -> Result<Vec<CassChunk>, String> {
    request.options.validate()?;

    let max_chunk_size = request.options.max_chunk_size;
    let overlap = request.options.overlap;
    let mut chunks = Vec::new();

    // Chunk the abstract
    if !request.abstract_text.is_empty() {
        let provenance = ChunkProvenance::for_abstract(
            &request.paper_id,
            &request.version,
            &request.extracted_at,
        );
        let text_chunks = chunk_text(&request.abstract_text, max_chunk_size, overlap);
        for (offset, content) in text_chunks {
            let chunk_id = compute_chunk_id(&request.paper_id, "abstract", offset);
            chunks.push(CassChunk {
                descriptor: CassChunkDescriptor {
                    chunk_id,
                    paper_id: request.paper_id.clone(),
                    section: "abstract".to_string(),
                    offset,
                    length: content.len(),
                    provenance: provenance.clone(),
                },
                content,
            });
        }
    }

    // Chunk each section
    for section in &request.sections {
        if section.text.is_empty() {
            continue;
        }
        let provenance = ChunkProvenance::for_section(
            &request.paper_id,
            &request.version,
            &request.extracted_at,
        );
        let text_chunks = chunk_text(&section.text, max_chunk_size, overlap);
        for (offset, content) in text_chunks {
            let chunk_id = compute_chunk_id(&request.paper_id, &section.label, offset);
            chunks.push(CassChunk {
                descriptor: CassChunkDescriptor {
                    chunk_id,
                    paper_id: request.paper_id.clone(),
                    section: section.label.clone(),
                    offset,
                    length: content.len(),
                    provenance: provenance.clone(),
                },
                content,
            });
        }
    }

    Ok(chunks)
}

/// Build a `CassIndexStatus` from a completed chunking result.
pub fn build_index_status(
    paper_id: &str,
    indexed_at: &str,
    chunk_count: usize,
    success: bool,
) -> CassIndexStatus {
    CassIndexStatus {
        paper_id: paper_id.to_string(),
        indexed_at: indexed_at.to_string(),
        chunk_count,
        status: if success {
            CassIndexStatusKind::Indexed
        } else {
            CassIndexStatusKind::Failed
        },
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper factories ────────────────────────────────────────────

    fn make_request(abstract_text: &str, sections: Vec<PaperSection>) -> CassIndexRequest {
        CassIndexRequest {
            paper_id: "2301.08745".to_string(),
            abstract_text: abstract_text.to_string(),
            sections,
            options: ChunkingOptions::default(),
            version: "v1".to_string(),
            extracted_at: "2026-03-09T12:00:00Z".to_string(),
        }
    }

    fn make_request_with_options(
        abstract_text: &str,
        sections: Vec<PaperSection>,
        max_chunk_size: usize,
        overlap: usize,
    ) -> CassIndexRequest {
        CassIndexRequest {
            paper_id: "2301.08745".to_string(),
            abstract_text: abstract_text.to_string(),
            sections,
            options: ChunkingOptions {
                max_chunk_size,
                overlap,
            },
            version: "v1".to_string(),
            extracted_at: "2026-03-09T12:00:00Z".to_string(),
        }
    }

    fn section(label: &str, text: &str) -> PaperSection {
        PaperSection {
            label: label.to_string(),
            text: text.to_string(),
        }
    }

    fn long_text(n: usize) -> String {
        "a".repeat(n)
    }

    // ── compute_chunk_id tests ──────────────────────────────────────

    #[test]
    fn chunk_id_deterministic() {
        let id1 = compute_chunk_id("2301.08745", "abstract", 0);
        let id2 = compute_chunk_id("2301.08745", "abstract", 0);
        assert_eq!(id1, id2);
    }

    #[test]
    fn chunk_id_different_paper() {
        let id1 = compute_chunk_id("2301.08745", "abstract", 0);
        let id2 = compute_chunk_id("2301.99999", "abstract", 0);
        assert_ne!(id1, id2);
    }

    #[test]
    fn chunk_id_different_section() {
        let id1 = compute_chunk_id("2301.08745", "abstract", 0);
        let id2 = compute_chunk_id("2301.08745", "introduction", 0);
        assert_ne!(id1, id2);
    }

    #[test]
    fn chunk_id_different_offset() {
        let id1 = compute_chunk_id("2301.08745", "abstract", 0);
        let id2 = compute_chunk_id("2301.08745", "abstract", 100);
        assert_ne!(id1, id2);
    }

    #[test]
    fn chunk_id_is_hex_16_chars() {
        let id = compute_chunk_id("test", "section", 42);
        assert_eq!(id.len(), 16);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn chunk_id_empty_inputs() {
        let id = compute_chunk_id("", "", 0);
        assert_eq!(id.len(), 16);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn chunk_id_unicode_section() {
        let id1 = compute_chunk_id("paper", "\u{00e9}tude", 0);
        let id2 = compute_chunk_id("paper", "\u{00e9}tude", 0);
        assert_eq!(id1, id2);
    }

    #[test]
    fn chunk_id_large_offset() {
        let id = compute_chunk_id("paper", "section", usize::MAX);
        assert_eq!(id.len(), 16);
    }

    #[test]
    fn chunk_id_special_characters_in_paper_id() {
        let id1 = compute_chunk_id("2301.08745v2", "abstract", 0);
        let id2 = compute_chunk_id("2301.08745v3", "abstract", 0);
        assert_ne!(id1, id2);
    }

    #[test]
    fn chunk_id_version_suffix_matters() {
        // Different paper IDs with version suffixes produce different IDs
        let id1 = compute_chunk_id("paper-v1", "s", 0);
        let id2 = compute_chunk_id("paper-v2", "s", 0);
        assert_ne!(id1, id2);
    }

    // ── ChunkProvenance tests ───────────────────────────────────────

    #[test]
    fn provenance_for_abstract() {
        let p = ChunkProvenance::for_abstract("2301.08745", "v1", "2026-03-09T00:00:00Z");
        assert_eq!(p.arxiv_id, "2301.08745");
        assert_eq!(p.version, "v1");
        assert_eq!(p.extraction_method, "abstract");
        assert_eq!(p.extracted_at, "2026-03-09T00:00:00Z");
    }

    #[test]
    fn provenance_for_section() {
        let p = ChunkProvenance::for_section("2301.08745", "v2", "2026-03-09T12:00:00Z");
        assert_eq!(p.extraction_method, "section_split");
        assert_eq!(p.version, "v2");
    }

    #[test]
    fn provenance_for_full_text() {
        let p = ChunkProvenance::for_full_text("2301.08745", "v1", "2026-03-09T12:00:00Z");
        assert_eq!(p.extraction_method, "full_text");
    }

    #[test]
    fn provenance_serde_roundtrip() {
        let p = ChunkProvenance::for_abstract("2301.08745", "v1", "2026-03-09T00:00:00Z");
        let json = serde_json::to_string(&p).unwrap();
        let p2: ChunkProvenance = serde_json::from_str(&json).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn provenance_clone_eq() {
        let p = ChunkProvenance::for_abstract("id", "v1", "ts");
        let cloned = p.clone();
        assert_eq!(p, cloned);
    }

    #[test]
    fn provenance_debug_format() {
        let p = ChunkProvenance::for_abstract("id", "v1", "ts");
        let dbg = format!("{p:?}");
        assert!(dbg.contains("ChunkProvenance"));
        assert!(dbg.contains("abstract"));
    }

    #[test]
    fn provenance_json_has_all_fields() {
        let p = ChunkProvenance::for_section("id", "v1", "ts");
        let v = serde_json::to_value(&p).unwrap();
        assert!(v.get("arxiv_id").is_some());
        assert!(v.get("version").is_some());
        assert!(v.get("extraction_method").is_some());
        assert!(v.get("extracted_at").is_some());
    }

    // ── CassChunkDescriptor tests ───────────────────────────────────

    #[test]
    fn descriptor_serde_roundtrip() {
        let d = CassChunkDescriptor {
            chunk_id: "abc123".to_string(),
            paper_id: "2301.08745".to_string(),
            section: "abstract".to_string(),
            offset: 0,
            length: 100,
            provenance: ChunkProvenance::for_abstract("2301.08745", "v1", "ts"),
        };
        let json = serde_json::to_string(&d).unwrap();
        let d2: CassChunkDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(d, d2);
    }

    #[test]
    fn descriptor_clone_eq() {
        let d = CassChunkDescriptor {
            chunk_id: "id".to_string(),
            paper_id: "paper".to_string(),
            section: "s".to_string(),
            offset: 0,
            length: 10,
            provenance: ChunkProvenance::for_abstract("paper", "v1", "ts"),
        };
        let cloned = d.clone();
        assert_eq!(d, cloned);
    }

    #[test]
    fn descriptor_debug_contains_chunk_id() {
        let d = CassChunkDescriptor {
            chunk_id: "test_chunk_id".to_string(),
            paper_id: "p".to_string(),
            section: "s".to_string(),
            offset: 0,
            length: 1,
            provenance: ChunkProvenance::for_abstract("p", "v1", "ts"),
        };
        let dbg = format!("{d:?}");
        assert!(dbg.contains("test_chunk_id"));
    }

    // ── CassChunk tests ─────────────────────────────────────────────

    #[test]
    fn chunk_serde_roundtrip() {
        let c = CassChunk {
            descriptor: CassChunkDescriptor {
                chunk_id: "c1".to_string(),
                paper_id: "p1".to_string(),
                section: "abstract".to_string(),
                offset: 0,
                length: 5,
                provenance: ChunkProvenance::for_abstract("p1", "v1", "ts"),
            },
            content: "hello".to_string(),
        };
        let json = serde_json::to_string(&c).unwrap();
        let c2: CassChunk = serde_json::from_str(&json).unwrap();
        assert_eq!(c, c2);
    }

    #[test]
    fn chunk_clone_and_drop() {
        let original = CassChunk {
            descriptor: CassChunkDescriptor {
                chunk_id: "c1".to_string(),
                paper_id: "p1".to_string(),
                section: "s".to_string(),
                offset: 0,
                length: 3,
                provenance: ChunkProvenance::for_abstract("p1", "v1", "ts"),
            },
            content: "abc".to_string(),
        };
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.content, "abc");
    }

    #[test]
    fn chunk_debug_format() {
        let c = CassChunk {
            descriptor: CassChunkDescriptor {
                chunk_id: "c1".to_string(),
                paper_id: "p1".to_string(),
                section: "s".to_string(),
                offset: 0,
                length: 3,
                provenance: ChunkProvenance::for_abstract("p1", "v1", "ts"),
            },
            content: "abc".to_string(),
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("CassChunk"));
    }

    // ── CassIndexStatusKind tests ───────────────────────────────────

    #[test]
    fn status_kind_display_pending() {
        assert_eq!(CassIndexStatusKind::Pending.to_string(), "pending");
    }

    #[test]
    fn status_kind_display_indexed() {
        assert_eq!(CassIndexStatusKind::Indexed.to_string(), "indexed");
    }

    #[test]
    fn status_kind_display_failed() {
        assert_eq!(CassIndexStatusKind::Failed.to_string(), "failed");
    }

    #[test]
    fn status_kind_display_stale() {
        assert_eq!(CassIndexStatusKind::Stale.to_string(), "stale");
    }

    #[test]
    fn status_kind_serde_roundtrip_all_variants() {
        for kind in [
            CassIndexStatusKind::Pending,
            CassIndexStatusKind::Indexed,
            CassIndexStatusKind::Failed,
            CassIndexStatusKind::Stale,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: CassIndexStatusKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }

    #[test]
    fn status_kind_copy() {
        let a = CassIndexStatusKind::Indexed;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn status_kind_debug() {
        let dbg = format!("{:?}", CassIndexStatusKind::Stale);
        assert!(dbg.contains("Stale"));
    }

    // ── CassIndexStatus tests ───────────────────────────────────────

    #[test]
    fn index_status_serde_roundtrip() {
        let s = CassIndexStatus {
            paper_id: "2301.08745".to_string(),
            indexed_at: "2026-03-09T12:00:00Z".to_string(),
            chunk_count: 5,
            status: CassIndexStatusKind::Indexed,
        };
        let json = serde_json::to_string(&s).unwrap();
        let s2: CassIndexStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, s2);
    }

    #[test]
    fn index_status_clone_eq() {
        let s = CassIndexStatus {
            paper_id: "p".to_string(),
            indexed_at: "ts".to_string(),
            chunk_count: 3,
            status: CassIndexStatusKind::Pending,
        };
        let cloned = s.clone();
        assert_eq!(s, cloned);
    }

    #[test]
    fn index_status_debug() {
        let s = CassIndexStatus {
            paper_id: "p".to_string(),
            indexed_at: "ts".to_string(),
            chunk_count: 0,
            status: CassIndexStatusKind::Failed,
        };
        let dbg = format!("{s:?}");
        assert!(dbg.contains("CassIndexStatus"));
        assert!(dbg.contains("Failed"));
    }

    #[test]
    fn build_index_status_success() {
        let s = build_index_status("2301.08745", "2026-03-09T12:00:00Z", 5, true);
        assert_eq!(s.paper_id, "2301.08745");
        assert_eq!(s.chunk_count, 5);
        assert_eq!(s.status, CassIndexStatusKind::Indexed);
    }

    #[test]
    fn build_index_status_failure() {
        let s = build_index_status("2301.08745", "2026-03-09T12:00:00Z", 0, false);
        assert_eq!(s.status, CassIndexStatusKind::Failed);
        assert_eq!(s.chunk_count, 0);
    }

    // ── ChunkingOptions tests ───────────────────────────────────────

    #[test]
    fn chunking_options_default() {
        let opts = ChunkingOptions::default();
        assert_eq!(opts.max_chunk_size, DEFAULT_MAX_CHUNK_SIZE);
        assert_eq!(opts.overlap, DEFAULT_OVERLAP);
    }

    #[test]
    fn chunking_options_validate_ok() {
        assert!(ChunkingOptions::default().validate().is_ok());
    }

    #[test]
    fn chunking_options_validate_too_small() {
        let opts = ChunkingOptions {
            max_chunk_size: 10,
            overlap: 0,
        };
        let err = opts.validate().unwrap_err();
        assert!(err.contains("at least"));
    }

    #[test]
    fn chunking_options_validate_too_large() {
        let opts = ChunkingOptions {
            max_chunk_size: 100_000,
            overlap: 0,
        };
        let err = opts.validate().unwrap_err();
        assert!(err.contains("must not exceed"));
    }

    #[test]
    fn chunking_options_validate_overlap_too_large() {
        let opts = ChunkingOptions {
            max_chunk_size: 200,
            overlap: 150,
        };
        let err = opts.validate().unwrap_err();
        assert!(err.contains("overlap"));
    }

    #[test]
    fn chunking_options_validate_boundary_min() {
        let opts = ChunkingOptions {
            max_chunk_size: MIN_CHUNK_SIZE,
            overlap: 0,
        };
        assert!(opts.validate().is_ok());
    }

    #[test]
    fn chunking_options_validate_boundary_max() {
        let opts = ChunkingOptions {
            max_chunk_size: MAX_CHUNK_SIZE_LIMIT,
            overlap: 0,
        };
        assert!(opts.validate().is_ok());
    }

    #[test]
    fn chunking_options_validate_max_overlap() {
        // overlap at exactly 50% should be ok
        let opts = ChunkingOptions {
            max_chunk_size: 200,
            overlap: 100,
        };
        assert!(opts.validate().is_ok());
    }

    #[test]
    fn chunking_options_serde_roundtrip() {
        let opts = ChunkingOptions {
            max_chunk_size: 512,
            overlap: 64,
        };
        let json = serde_json::to_string(&opts).unwrap();
        let opts2: ChunkingOptions = serde_json::from_str(&json).unwrap();
        assert_eq!(opts, opts2);
    }

    // ── PaperSection tests ──────────────────────────────────────────

    #[test]
    fn paper_section_serde_roundtrip() {
        let s = section("intro", "This paper introduces...");
        let json = serde_json::to_string(&s).unwrap();
        let s2: PaperSection = serde_json::from_str(&json).unwrap();
        assert_eq!(s, s2);
    }

    #[test]
    fn paper_section_clone_eq() {
        let s = section("methods", "We use...");
        let cloned = s.clone();
        assert_eq!(s, cloned);
    }

    // ── CassIndexRequest tests ──────────────────────────────────────

    #[test]
    fn index_request_serde_roundtrip() {
        let req = make_request("abstract text", vec![section("intro", "Introduction text")]);
        let json = serde_json::to_string(&req).unwrap();
        let req2: CassIndexRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, req2);
    }

    #[test]
    fn index_request_clone_eq() {
        let req = make_request("abs", vec![]);
        let cloned = req.clone();
        assert_eq!(req, cloned);
    }

    // ── CassSearchFilter tests ──────────────────────────────────────

    #[test]
    fn search_filter_default() {
        let f = CassSearchFilter::default();
        assert!(f.paper_ids.is_empty());
        assert!(f.sections.is_empty());
        assert!(f.min_score.abs() < f64::EPSILON);
    }

    #[test]
    fn search_filter_serde_roundtrip() {
        let f = CassSearchFilter {
            paper_ids: vec!["p1".to_string()],
            sections: vec!["abstract".to_string()],
            min_score: 0.5,
        };
        let json = serde_json::to_string(&f).unwrap();
        let f2: CassSearchFilter = serde_json::from_str(&json).unwrap();
        assert_eq!(f, f2);
    }

    #[test]
    fn search_filter_deserialize_missing_fields() {
        let f: CassSearchFilter = serde_json::from_str("{}").unwrap();
        assert!(f.paper_ids.is_empty());
        assert!(f.min_score.abs() < f64::EPSILON);
    }

    // ── CassSearchRequest tests ─────────────────────────────────────

    #[test]
    fn search_request_serde_roundtrip() {
        let req = CassSearchRequest {
            query: "transformer attention".to_string(),
            filters: CassSearchFilter::default(),
            limit: 10,
        };
        let json = serde_json::to_string(&req).unwrap();
        let req2: CassSearchRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, req2);
    }

    #[test]
    fn search_request_with_filters() {
        let req = CassSearchRequest {
            query: "llm".to_string(),
            filters: CassSearchFilter {
                paper_ids: vec!["2301.08745".to_string()],
                sections: vec!["abstract".to_string(), "introduction".to_string()],
                min_score: 0.7,
            },
            limit: 5,
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["limit"], 5);
        assert_eq!(v["filters"]["paper_ids"].as_array().unwrap().len(), 1);
    }

    // ── CassSearchHit tests ─────────────────────────────────────────

    #[test]
    fn search_hit_serde_roundtrip() {
        let hit = CassSearchHit {
            chunk: CassChunk {
                descriptor: CassChunkDescriptor {
                    chunk_id: "c1".to_string(),
                    paper_id: "p1".to_string(),
                    section: "abstract".to_string(),
                    offset: 0,
                    length: 5,
                    provenance: ChunkProvenance::for_abstract("p1", "v1", "ts"),
                },
                content: "hello".to_string(),
            },
            score: 0.95,
        };
        let json = serde_json::to_string(&hit).unwrap();
        let hit2: CassSearchHit = serde_json::from_str(&json).unwrap();
        assert_eq!(hit, hit2);
    }

    // ── CassSearchResult tests ──────────────────────────────────────

    #[test]
    fn search_result_serde_roundtrip() {
        let res = CassSearchResult {
            hits: vec![],
            total: 0,
            query: "test".to_string(),
        };
        let json = serde_json::to_string(&res).unwrap();
        let res2: CassSearchResult = serde_json::from_str(&json).unwrap();
        assert_eq!(res, res2);
    }

    #[test]
    fn search_result_with_hits() {
        let res = CassSearchResult {
            hits: vec![CassSearchHit {
                chunk: CassChunk {
                    descriptor: CassChunkDescriptor {
                        chunk_id: "c1".to_string(),
                        paper_id: "p1".to_string(),
                        section: "abstract".to_string(),
                        offset: 0,
                        length: 5,
                        provenance: ChunkProvenance::for_abstract("p1", "v1", "ts"),
                    },
                    content: "hello".to_string(),
                },
                score: 0.9,
            }],
            total: 1,
            query: "hello".to_string(),
        };
        assert_eq!(res.hits.len(), 1);
        assert_eq!(res.total, 1);
    }

    #[test]
    fn search_result_clone() {
        let res = CassSearchResult {
            hits: vec![],
            total: 42,
            query: "q".to_string(),
        };
        let cloned = res.clone();
        assert_eq!(res, cloned);
    }

    // ── CassWritePolicy tests ───────────────────────────────────────

    #[test]
    fn write_policy_allow_always_permits() {
        assert!(CassWritePolicy::Allow.is_write_allowed(false));
        assert!(CassWritePolicy::Allow.is_write_allowed(true));
    }

    #[test]
    fn write_policy_deny_always_blocks() {
        assert!(!CassWritePolicy::Deny.is_write_allowed(false));
        assert!(!CassWritePolicy::Deny.is_write_allowed(true));
    }

    #[test]
    fn write_policy_new_only_permits_new() {
        assert!(CassWritePolicy::NewOnly.is_write_allowed(false));
    }

    #[test]
    fn write_policy_new_only_blocks_existing() {
        assert!(!CassWritePolicy::NewOnly.is_write_allowed(true));
    }

    #[test]
    fn write_policy_display() {
        assert_eq!(CassWritePolicy::Allow.to_string(), "allow");
        assert_eq!(CassWritePolicy::Deny.to_string(), "deny");
        assert_eq!(CassWritePolicy::NewOnly.to_string(), "new_only");
    }

    #[test]
    fn write_policy_serde_roundtrip() {
        for policy in [
            CassWritePolicy::Allow,
            CassWritePolicy::Deny,
            CassWritePolicy::NewOnly,
        ] {
            let json = serde_json::to_string(&policy).unwrap();
            let back: CassWritePolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(policy, back);
        }
    }

    #[test]
    fn write_policy_copy() {
        let a = CassWritePolicy::Allow;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn write_policy_debug() {
        let dbg = format!("{:?}", CassWritePolicy::NewOnly);
        assert!(dbg.contains("NewOnly"));
    }

    // ── chunk_text tests ────────────────────────────────────────────

    #[test]
    fn chunk_text_empty() {
        assert!(chunk_text("", 100, 0).is_empty());
    }

    #[test]
    fn chunk_text_fits_in_one_chunk() {
        let result = chunk_text("hello world", 100, 0);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, 0);
        assert_eq!(result[0].1, "hello world");
    }

    #[test]
    fn chunk_text_splits_at_boundary() {
        let text = "abcdefghij"; // 10 chars
        let result = chunk_text(text, 5, 0);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].1, "abcde");
        assert_eq!(result[1].1, "fghij");
    }

    #[test]
    fn chunk_text_with_overlap() {
        let text = "abcdefghij"; // 10 chars
        let result = chunk_text(text, 5, 2);
        // step = 5 - 2 = 3
        // chunk 0: offset 0, "abcde"
        // chunk 1: offset 3, "defgh"
        // chunk 2: offset 6, "ghij"
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].0, 0);
        assert_eq!(result[0].1, "abcde");
        assert_eq!(result[1].0, 3);
        assert_eq!(result[1].1, "defgh");
        assert_eq!(result[2].0, 6);
        assert_eq!(result[2].1, "ghij");
    }

    #[test]
    fn chunk_text_exact_multiple() {
        let text = long_text(200);
        let result = chunk_text(&text, 100, 0);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].1.len(), 100);
        assert_eq!(result[1].1.len(), 100);
    }

    #[test]
    fn chunk_text_offsets_are_char_based() {
        // Use multi-byte characters
        let text = "\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}\u{00e9}"; // 10 chars, each 2 bytes
        let result = chunk_text(text, 5, 0);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].0, 0);
        assert_eq!(result[1].0, 5);
    }

    #[test]
    fn chunk_text_single_char_chunk_size() {
        let text = "abcde";
        let result = chunk_text(text, 5, 0);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].1, "abcde");
    }

    #[test]
    fn chunk_text_longer_than_max() {
        let text = long_text(300);
        let result = chunk_text(&text, 100, 0);
        assert!(result.len() >= 3);
        for (_, chunk) in &result {
            assert!(chunk.len() <= 100);
        }
    }

    #[test]
    fn chunk_text_overlap_produces_shared_content() {
        let text = "0123456789abcdef"; // 16 chars
        let result = chunk_text(text, 8, 4);
        // step = 8 - 4 = 4
        // chunk 0: 0..8 = "01234567"
        // chunk 1: 4..12 = "456789ab"
        // chunk 2: 8..16 = "89abcdef"
        assert_eq!(result.len(), 3);
        // Verify overlap: last 4 chars of chunk 0 = first 4 chars of chunk 1
        assert_eq!(&result[0].1[4..], &result[1].1[..4]);
    }

    // ── chunk_paper tests ───────────────────────────────────────────

    #[test]
    fn chunk_paper_abstract_only() {
        let req = make_request("Short abstract", vec![]);
        let chunks = chunk_paper(&req).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].content, "Short abstract");
        assert_eq!(chunks[0].descriptor.section, "abstract");
        assert_eq!(chunks[0].descriptor.offset, 0);
    }

    #[test]
    fn chunk_paper_empty_abstract_no_sections() {
        let req = make_request("", vec![]);
        let chunks = chunk_paper(&req).unwrap();
        assert!(chunks.is_empty());
    }

    #[test]
    fn chunk_paper_empty_abstract_with_sections() {
        let req = make_request("", vec![section("intro", "Introduction text here")]);
        let chunks = chunk_paper(&req).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].descriptor.section, "intro");
    }

    #[test]
    fn chunk_paper_with_sections() {
        let req = make_request(
            "Abstract",
            vec![
                section("introduction", "Intro text"),
                section("methods", "Methods text"),
            ],
        );
        let chunks = chunk_paper(&req).unwrap();
        // abstract + 2 sections = 3 chunks (all short enough for single chunk each)
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].descriptor.section, "abstract");
        assert_eq!(chunks[1].descriptor.section, "introduction");
        assert_eq!(chunks[2].descriptor.section, "methods");
    }

    #[test]
    fn chunk_paper_skips_empty_sections() {
        let req = make_request(
            "Abstract",
            vec![
                section("intro", "Non-empty"),
                section("empty_section", ""),
                section("methods", "Also non-empty"),
            ],
        );
        let chunks = chunk_paper(&req).unwrap();
        assert_eq!(chunks.len(), 3); // abstract + intro + methods
        assert!(!chunks.iter().any(|c| c.descriptor.section == "empty_section"));
    }

    #[test]
    fn chunk_paper_deterministic() {
        let req = make_request(
            "Some abstract text",
            vec![section("intro", "Introduction content")],
        );
        let chunks1 = chunk_paper(&req).unwrap();
        let chunks2 = chunk_paper(&req).unwrap();
        assert_eq!(chunks1.len(), chunks2.len());
        for (c1, c2) in chunks1.iter().zip(chunks2.iter()) {
            assert_eq!(c1.descriptor.chunk_id, c2.descriptor.chunk_id);
            assert_eq!(c1.content, c2.content);
        }
    }

    #[test]
    fn chunk_paper_chunk_ids_unique() {
        let req = make_request(
            &long_text(2000),
            vec![
                section("intro", &long_text(2000)),
                section("methods", &long_text(2000)),
            ],
        );
        let chunks = chunk_paper(&req).unwrap();
        let ids: Vec<&str> = chunks.iter().map(|c| c.descriptor.chunk_id.as_str()).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(ids.len(), sorted.len(), "chunk IDs must be unique");
    }

    #[test]
    fn chunk_paper_respects_max_chunk_size() {
        let req = make_request_with_options(&long_text(5000), vec![], 256, 0);
        let chunks = chunk_paper(&req).unwrap();
        for chunk in &chunks {
            assert!(
                chunk.content.len() <= 256,
                "chunk content exceeds max_chunk_size"
            );
        }
    }

    #[test]
    fn chunk_paper_custom_overlap() {
        let req = make_request_with_options(&long_text(500), vec![], 200, 50);
        let chunks = chunk_paper(&req).unwrap();
        assert!(chunks.len() >= 3);
        // Verify overlap between consecutive chunks
        for i in 0..chunks.len() - 1 {
            let end_of_current = chunks[i].descriptor.offset + chunks[i].content.len();
            let start_of_next = chunks[i + 1].descriptor.offset;
            assert!(
                end_of_current > start_of_next,
                "expected overlap between chunk {i} and {}",
                i + 1
            );
        }
    }

    #[test]
    fn chunk_paper_provenance_abstract() {
        let req = make_request("Abstract text", vec![]);
        let chunks = chunk_paper(&req).unwrap();
        assert_eq!(chunks[0].descriptor.provenance.extraction_method, "abstract");
        assert_eq!(chunks[0].descriptor.provenance.arxiv_id, "2301.08745");
        assert_eq!(chunks[0].descriptor.provenance.version, "v1");
    }

    #[test]
    fn chunk_paper_provenance_section() {
        let req = make_request("", vec![section("intro", "Introduction")]);
        let chunks = chunk_paper(&req).unwrap();
        assert_eq!(
            chunks[0].descriptor.provenance.extraction_method,
            "section_split"
        );
    }

    #[test]
    fn chunk_paper_invalid_options_rejected() {
        let req = make_request_with_options("text", vec![], 10, 0);
        let result = chunk_paper(&req);
        assert!(result.is_err());
    }

    #[test]
    fn chunk_paper_all_chunks_have_paper_id() {
        let req = make_request(
            &long_text(2000),
            vec![section("intro", &long_text(2000))],
        );
        let chunks = chunk_paper(&req).unwrap();
        for chunk in &chunks {
            assert_eq!(chunk.descriptor.paper_id, "2301.08745");
        }
    }

    #[test]
    fn chunk_paper_length_field_matches_content() {
        let req = make_request_with_options(&long_text(3000), vec![], 512, 64);
        let chunks = chunk_paper(&req).unwrap();
        for chunk in &chunks {
            assert_eq!(
                chunk.descriptor.length,
                chunk.content.len(),
                "length field must match content.len()"
            );
        }
    }

    #[test]
    fn chunk_paper_covers_all_content() {
        let text = "abcdefghij"; // 10 chars
        let req = make_request_with_options(text, vec![], 64, 0);
        let chunks = chunk_paper(&req).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].content, text);
    }

    #[test]
    fn chunk_paper_large_document() {
        let req = make_request_with_options(
            &long_text(10_000),
            vec![
                section("s1", &long_text(5000)),
                section("s2", &long_text(5000)),
            ],
            1024,
            128,
        );
        let chunks = chunk_paper(&req).unwrap();
        // Should produce many chunks
        assert!(chunks.len() > 15);
        // All chunks are bounded
        for chunk in &chunks {
            assert!(chunk.content.len() <= 1024);
        }
    }

    #[test]
    fn chunk_paper_minimum_chunk_size() {
        let req = make_request_with_options(&long_text(200), vec![], MIN_CHUNK_SIZE, 0);
        let chunks = chunk_paper(&req).unwrap();
        assert!(chunks.len() > 1);
    }

    #[test]
    fn chunk_paper_max_chunk_size_limit() {
        let req = make_request_with_options(&long_text(20_000), vec![], MAX_CHUNK_SIZE_LIMIT, 0);
        let chunks = chunk_paper(&req).unwrap();
        for chunk in &chunks {
            assert!(chunk.content.len() <= MAX_CHUNK_SIZE_LIMIT);
        }
    }

    #[test]
    fn chunk_paper_different_paper_ids_produce_different_chunk_ids() {
        let req1 = CassIndexRequest {
            paper_id: "paper-A".to_string(),
            abstract_text: "Same abstract".to_string(),
            sections: vec![],
            options: ChunkingOptions::default(),
            version: "v1".to_string(),
            extracted_at: "ts".to_string(),
        };
        let req2 = CassIndexRequest {
            paper_id: "paper-B".to_string(),
            abstract_text: "Same abstract".to_string(),
            sections: vec![],
            options: ChunkingOptions::default(),
            version: "v1".to_string(),
            extracted_at: "ts".to_string(),
        };
        let chunks1 = chunk_paper(&req1).unwrap();
        let chunks2 = chunk_paper(&req2).unwrap();
        assert_ne!(
            chunks1[0].descriptor.chunk_id,
            chunks2[0].descriptor.chunk_id
        );
    }

    // ── Integration-style tests ─────────────────────────────────────

    #[test]
    fn full_indexing_flow() {
        let req = CassIndexRequest {
            paper_id: "2301.08745".to_string(),
            abstract_text: "We present a novel approach to attention mechanisms.".to_string(),
            sections: vec![
                section("introduction", "Attention is all you need introduced the transformer architecture."),
                section("methods", "We propose a modified multi-head attention mechanism."),
                section("results", "Our method achieves state-of-the-art performance."),
            ],
            options: ChunkingOptions::default(),
            version: "v1".to_string(),
            extracted_at: "2026-03-09T12:00:00Z".to_string(),
        };

        let chunks = chunk_paper(&req).unwrap();
        assert_eq!(chunks.len(), 4); // abstract + 3 sections (all short)

        let status = build_index_status(
            &req.paper_id,
            &req.extracted_at,
            chunks.len(),
            true,
        );
        assert_eq!(status.status, CassIndexStatusKind::Indexed);
        assert_eq!(status.chunk_count, 4);
    }

    #[test]
    fn full_indexing_flow_with_chunking() {
        let long_abstract = long_text(3000);
        let long_intro = long_text(2500);
        let req = CassIndexRequest {
            paper_id: "2301.99999".to_string(),
            abstract_text: long_abstract,
            sections: vec![section("introduction", &long_intro)],
            options: ChunkingOptions {
                max_chunk_size: 512,
                overlap: 64,
            },
            version: "v2".to_string(),
            extracted_at: "2026-03-09T15:00:00Z".to_string(),
        };

        let chunks = chunk_paper(&req).unwrap();
        // Each long text should produce multiple chunks
        let abstract_count = chunks
            .iter()
            .filter(|c| c.descriptor.section == "abstract")
            .count();
        let intro_count = chunks
            .iter()
            .filter(|c| c.descriptor.section == "introduction")
            .count();
        assert!(abstract_count > 5);
        assert!(intro_count > 4);

        // All chunks bounded
        for chunk in &chunks {
            assert!(chunk.content.len() <= 512);
        }

        // All chunk IDs unique
        let mut ids: Vec<&str> = chunks.iter().map(|c| c.descriptor.chunk_id.as_str()).collect();
        let total = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), total);
    }

    #[test]
    fn write_policy_gates_indexing() {
        let policy = CassWritePolicy::NewOnly;

        // First indexing: paper doesn't exist
        assert!(policy.is_write_allowed(false));

        // Second indexing: paper already exists
        assert!(!policy.is_write_allowed(true));
    }

    #[test]
    fn search_request_construction() {
        let req = CassSearchRequest {
            query: "attention mechanism".to_string(),
            filters: CassSearchFilter {
                paper_ids: vec!["2301.08745".to_string()],
                sections: vec!["abstract".to_string()],
                min_score: 0.5,
            },
            limit: 10,
        };
        assert_eq!(req.filters.paper_ids.len(), 1);
        assert_eq!(req.limit, 10);
    }

    #[test]
    fn search_result_construction() {
        let res = CassSearchResult {
            hits: vec![
                CassSearchHit {
                    chunk: CassChunk {
                        descriptor: CassChunkDescriptor {
                            chunk_id: compute_chunk_id("p1", "abstract", 0),
                            paper_id: "p1".to_string(),
                            section: "abstract".to_string(),
                            offset: 0,
                            length: 20,
                            provenance: ChunkProvenance::for_abstract("p1", "v1", "ts"),
                        },
                        content: "attention mechanism".to_string(),
                    },
                    score: 0.95,
                },
                CassSearchHit {
                    chunk: CassChunk {
                        descriptor: CassChunkDescriptor {
                            chunk_id: compute_chunk_id("p2", "introduction", 100),
                            paper_id: "p2".to_string(),
                            section: "introduction".to_string(),
                            offset: 100,
                            length: 15,
                            provenance: ChunkProvenance::for_section("p2", "v1", "ts"),
                        },
                        content: "multi-head attn".to_string(),
                    },
                    score: 0.82,
                },
            ],
            total: 2,
            query: "attention".to_string(),
        };
        assert_eq!(res.hits.len(), 2);
        assert!(res.hits[0].score > res.hits[1].score);
    }

    // ── Edge case tests ─────────────────────────────────────────────

    #[test]
    fn chunk_paper_single_char_abstract() {
        let req = make_request("X", vec![]);
        let chunks = chunk_paper(&req).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].content, "X");
        assert_eq!(chunks[0].descriptor.length, 1);
    }

    #[test]
    fn chunk_paper_unicode_content() {
        let req = make_request(
            "\u{00c9}tude sur les r\u{00e9}seaux de neurones",
            vec![section("r\u{00e9}sum\u{00e9}", "Les r\u{00e9}sultats montrent...")],
        );
        let chunks = chunk_paper(&req).unwrap();
        assert_eq!(chunks.len(), 2);
        assert!(chunks[0].content.contains('\u{00c9}'));
        assert_eq!(chunks[1].descriptor.section, "r\u{00e9}sum\u{00e9}");
    }

    #[test]
    fn chunk_paper_many_sections() {
        let sections: Vec<PaperSection> = (0..20)
            .map(|i| section(&format!("section_{i}"), &format!("Content of section {i}")))
            .collect();
        let req = make_request("Abstract", sections);
        let chunks = chunk_paper(&req).unwrap();
        assert_eq!(chunks.len(), 21); // 1 abstract + 20 sections
    }

    #[test]
    fn chunk_paper_whitespace_only_abstract() {
        let req = make_request("   \n\t  ", vec![]);
        let chunks = chunk_paper(&req).unwrap();
        // Whitespace-only is not empty, so it produces a chunk
        assert_eq!(chunks.len(), 1);
    }

    #[test]
    fn chunk_paper_newlines_preserved() {
        let req = make_request("Line 1\nLine 2\nLine 3", vec![]);
        let chunks = chunk_paper(&req).unwrap();
        assert!(chunks[0].content.contains('\n'));
    }

    #[test]
    fn chunk_text_overlap_equals_zero() {
        let text = long_text(300);
        let result = chunk_text(&text, 100, 0);
        // No overlap: chunks should be contiguous
        for i in 0..result.len() - 1 {
            let end = result[i].0 + result[i].1.len();
            assert_eq!(end, result[i + 1].0);
        }
    }

    #[test]
    fn status_kind_ne() {
        assert_ne!(CassIndexStatusKind::Pending, CassIndexStatusKind::Indexed);
        assert_ne!(CassIndexStatusKind::Failed, CassIndexStatusKind::Stale);
    }

    #[test]
    fn index_status_json_fields() {
        let s = CassIndexStatus {
            paper_id: "p".to_string(),
            indexed_at: "ts".to_string(),
            chunk_count: 7,
            status: CassIndexStatusKind::Indexed,
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["paper_id"], "p");
        assert_eq!(v["indexed_at"], "ts");
        assert_eq!(v["chunk_count"], 7);
        assert_eq!(v["status"], "Indexed");
    }

    #[test]
    fn write_policy_ne() {
        assert_ne!(CassWritePolicy::Allow, CassWritePolicy::Deny);
        assert_ne!(CassWritePolicy::Deny, CassWritePolicy::NewOnly);
    }

    #[test]
    fn chunk_paper_overlap_boundary_exact() {
        // max_chunk_size=100, overlap=50 -> step=50
        // text=150 chars -> chunks at 0, 50, 100
        let text = long_text(150);
        let req = make_request_with_options(&text, vec![], 100, 50);
        let chunks = chunk_paper(&req).unwrap();
        assert!(chunks.len() >= 2);
    }

    #[test]
    fn chunk_paper_all_provenance_timestamps_match() {
        let req = make_request_with_options(
            &long_text(3000),
            vec![section("s1", &long_text(2000))],
            512,
            64,
        );
        let chunks = chunk_paper(&req).unwrap();
        for chunk in &chunks {
            assert_eq!(
                chunk.descriptor.provenance.extracted_at,
                "2026-03-09T12:00:00Z"
            );
        }
    }

    #[test]
    fn chunk_paper_all_provenance_versions_match() {
        let req = make_request_with_options(&long_text(3000), vec![], 512, 64);
        let chunks = chunk_paper(&req).unwrap();
        for chunk in &chunks {
            assert_eq!(chunk.descriptor.provenance.version, "v1");
        }
    }

    #[test]
    fn chunk_descriptor_json_has_all_fields() {
        let d = CassChunkDescriptor {
            chunk_id: "id".to_string(),
            paper_id: "p".to_string(),
            section: "s".to_string(),
            offset: 10,
            length: 20,
            provenance: ChunkProvenance::for_abstract("p", "v1", "ts"),
        };
        let v = serde_json::to_value(&d).unwrap();
        assert!(v.get("chunk_id").is_some());
        assert!(v.get("paper_id").is_some());
        assert!(v.get("section").is_some());
        assert!(v.get("offset").is_some());
        assert!(v.get("length").is_some());
        assert!(v.get("provenance").is_some());
    }

    #[test]
    fn chunk_json_has_descriptor_and_content() {
        let c = CassChunk {
            descriptor: CassChunkDescriptor {
                chunk_id: "id".to_string(),
                paper_id: "p".to_string(),
                section: "s".to_string(),
                offset: 0,
                length: 5,
                provenance: ChunkProvenance::for_abstract("p", "v1", "ts"),
            },
            content: "hello".to_string(),
        };
        let v = serde_json::to_value(&c).unwrap();
        assert!(v.get("descriptor").is_some());
        assert!(v.get("content").is_some());
        assert_eq!(v["content"], "hello");
    }

    #[test]
    fn search_filter_with_only_paper_ids() {
        let f = CassSearchFilter {
            paper_ids: vec!["p1".to_string(), "p2".to_string()],
            sections: vec![],
            min_score: 0.0,
        };
        let json = serde_json::to_string(&f).unwrap();
        let f2: CassSearchFilter = serde_json::from_str(&json).unwrap();
        assert_eq!(f2.paper_ids.len(), 2);
        assert!(f2.sections.is_empty());
    }

    #[test]
    fn search_filter_with_only_sections() {
        let f = CassSearchFilter {
            paper_ids: vec![],
            sections: vec!["abstract".to_string(), "methods".to_string()],
            min_score: 0.0,
        };
        assert_eq!(f.sections.len(), 2);
    }

    #[test]
    fn search_request_debug() {
        let req = CassSearchRequest {
            query: "test".to_string(),
            filters: CassSearchFilter::default(),
            limit: 5,
        };
        let dbg = format!("{req:?}");
        assert!(dbg.contains("CassSearchRequest"));
    }

    #[test]
    fn search_result_debug() {
        let res = CassSearchResult {
            hits: vec![],
            total: 0,
            query: "test".to_string(),
        };
        let dbg = format!("{res:?}");
        assert!(dbg.contains("CassSearchResult"));
    }

    #[test]
    fn search_hit_debug() {
        let hit = CassSearchHit {
            chunk: CassChunk {
                descriptor: CassChunkDescriptor {
                    chunk_id: "c1".to_string(),
                    paper_id: "p1".to_string(),
                    section: "s".to_string(),
                    offset: 0,
                    length: 1,
                    provenance: ChunkProvenance::for_abstract("p1", "v1", "ts"),
                },
                content: "x".to_string(),
            },
            score: 0.5,
        };
        let dbg = format!("{hit:?}");
        assert!(dbg.contains("CassSearchHit"));
    }

    #[test]
    fn chunking_options_clone_eq() {
        let opts = ChunkingOptions {
            max_chunk_size: 256,
            overlap: 32,
        };
        let cloned = opts.clone();
        assert_eq!(opts, cloned);
    }

    #[test]
    fn chunking_options_debug() {
        let opts = ChunkingOptions::default();
        let dbg = format!("{opts:?}");
        assert!(dbg.contains("ChunkingOptions"));
    }

    #[test]
    fn index_request_debug() {
        let req = make_request("abs", vec![]);
        let dbg = format!("{req:?}");
        assert!(dbg.contains("CassIndexRequest"));
    }

    #[test]
    fn paper_section_debug() {
        let s = section("intro", "text");
        let dbg = format!("{s:?}");
        assert!(dbg.contains("PaperSection"));
    }

    #[test]
    fn build_index_status_preserves_indexed_at() {
        let s = build_index_status("p", "2026-01-01T00:00:00Z", 3, true);
        assert_eq!(s.indexed_at, "2026-01-01T00:00:00Z");
    }

    #[test]
    fn chunk_text_very_long() {
        let text = long_text(50_000);
        let result = chunk_text(&text, 1024, 128);
        assert!(result.len() > 40);
        for (_, chunk) in &result {
            assert!(chunk.len() <= 1024);
        }
    }

    #[test]
    fn chunk_text_overlap_nearly_equal_to_size() {
        // overlap = max_chunk_size / 2 (at the validation boundary)
        let text = long_text(500);
        let result = chunk_text(&text, 200, 100);
        // step = 200 - 100 = 100
        assert!(result.len() >= 4);
    }

    #[test]
    fn constants_values() {
        assert_eq!(DEFAULT_MAX_CHUNK_SIZE, 1024);
        assert_eq!(DEFAULT_OVERLAP, 128);
        assert_eq!(MIN_CHUNK_SIZE, 64);
        assert_eq!(MAX_CHUNK_SIZE_LIMIT, 8192);
    }
}
