//! Semantic Scholar API types.

use serde::{Deserialize, Serialize};

/// A Semantic Scholar paper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Paper {
    #[serde(rename = "paperId")]
    pub paper_id: String,
    pub title: Option<String>,
    #[serde(rename = "abstract")]
    pub paper_abstract: Option<String>,
    pub year: Option<i64>,
    pub venue: Option<String>,
    #[serde(rename = "citationCount")]
    pub citation_count: Option<i64>,
    #[serde(rename = "referenceCount")]
    pub reference_count: Option<i64>,
    #[serde(rename = "influentialCitationCount")]
    pub influential_citation_count: Option<i64>,
    #[serde(rename = "isOpenAccess")]
    pub is_open_access: Option<bool>,
    pub url: Option<String>,
    pub authors: Option<Vec<AuthorSummary>>,
    #[serde(rename = "externalIds")]
    pub external_ids: Option<serde_json::Value>,
    pub tldr: Option<serde_json::Value>,
    #[serde(rename = "fieldsOfStudy")]
    pub fields_of_study: Option<Vec<String>>,
    #[serde(rename = "publicationTypes")]
    pub publication_types: Option<Vec<String>>,
    #[serde(rename = "publicationDate")]
    pub publication_date: Option<String>,
    pub journal: Option<serde_json::Value>,
}

/// A summary of an author (as embedded in paper responses).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorSummary {
    #[serde(rename = "authorId")]
    pub author_id: Option<String>,
    pub name: Option<String>,
}

/// A Semantic Scholar author (full detail).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Author {
    #[serde(rename = "authorId")]
    pub author_id: String,
    pub name: Option<String>,
    #[serde(rename = "hIndex")]
    pub h_index: Option<i64>,
    #[serde(rename = "citationCount")]
    pub citation_count: Option<i64>,
    #[serde(rename = "paperCount")]
    pub paper_count: Option<i64>,
    pub url: Option<String>,
    pub affiliations: Option<Vec<String>>,
    pub aliases: Option<Vec<String>>,
    #[serde(rename = "externalIds")]
    pub external_ids: Option<serde_json::Value>,
    pub homepage: Option<String>,
}

/// A citation or reference entry wrapping a cited/citing paper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CitationEdge {
    #[serde(rename = "citingPaper", alias = "citedPaper")]
    pub paper: Option<Paper>,
    pub contexts: Option<Vec<String>>,
    pub intents: Option<Vec<String>>,
    #[serde(rename = "isInfluential")]
    pub is_influential: Option<bool>,
}

/// Search response envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResponse {
    pub total: Option<i64>,
    pub offset: Option<i64>,
    pub next: Option<i64>,
    pub data: Vec<serde_json::Value>,
}

/// Citation/reference list response envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CitationListResponse {
    pub offset: Option<i64>,
    pub next: Option<i64>,
    pub data: Vec<serde_json::Value>,
}

/// Author papers list response envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorPapersResponse {
    pub offset: Option<i64>,
    pub next: Option<i64>,
    pub data: Vec<serde_json::Value>,
}

/// Recommendations response envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecommendationsResponse {
    #[serde(rename = "recommendedPapers")]
    pub recommended_papers: Vec<serde_json::Value>,
}

/// Semantic Scholar API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub error: Option<String>,
    pub message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn paper_roundtrip() {
        let p: Paper = serde_json::from_value(json!({
            "paperId": "abc123",
            "title": "Attention Is All You Need",
            "abstract": "We propose a new architecture...",
            "year": 2017,
            "venue": "NeurIPS",
            "citationCount": 50000,
            "referenceCount": 42,
            "influentialCitationCount": 5000,
            "isOpenAccess": true,
            "url": "https://www.semanticscholar.org/paper/abc123",
            "authors": [{"authorId": "1", "name": "Author A"}],
        }))
        .unwrap();
        assert_eq!(p.paper_id, "abc123");
        assert_eq!(p.title, Some("Attention Is All You Need".into()));
        assert_eq!(p.year, Some(2017));
        assert_eq!(p.citation_count, Some(50000));
        assert_eq!(p.is_open_access, Some(true));
        let re = serde_json::to_value(&p).unwrap();
        assert_eq!(re["paperId"], "abc123");
        assert_eq!(re["venue"], "NeurIPS");
    }

    #[test]
    fn paper_minimal() {
        let p: Paper = serde_json::from_value(json!({"paperId": "x"})).unwrap();
        assert_eq!(p.paper_id, "x");
        assert!(p.title.is_none());
        assert!(p.year.is_none());
        assert!(p.authors.is_none());
    }

    #[test]
    fn paper_with_abstract() {
        let p: Paper = serde_json::from_value(json!({
            "paperId": "p1",
            "abstract": "This paper explores...",
        }))
        .unwrap();
        assert_eq!(p.paper_abstract, Some("This paper explores...".into()));
    }

    #[test]
    fn paper_with_fields_of_study() {
        let p: Paper = serde_json::from_value(json!({
            "paperId": "p2",
            "fieldsOfStudy": ["Computer Science", "Mathematics"],
        }))
        .unwrap();
        assert_eq!(
            p.fields_of_study,
            Some(vec!["Computer Science".into(), "Mathematics".into()])
        );
    }

    #[test]
    fn paper_with_publication_types() {
        let p: Paper = serde_json::from_value(json!({
            "paperId": "p3",
            "publicationTypes": ["JournalArticle"],
        }))
        .unwrap();
        assert_eq!(
            p.publication_types,
            Some(vec!["JournalArticle".into()])
        );
    }

    #[test]
    fn author_summary_roundtrip() {
        let a: AuthorSummary = serde_json::from_value(json!({
            "authorId": "42",
            "name": "John Doe",
        }))
        .unwrap();
        assert_eq!(a.author_id, Some("42".into()));
        assert_eq!(a.name, Some("John Doe".into()));
    }

    #[test]
    fn author_summary_minimal() {
        let a: AuthorSummary = serde_json::from_value(json!({})).unwrap();
        assert!(a.author_id.is_none());
        assert!(a.name.is_none());
    }

    #[test]
    fn author_roundtrip() {
        let a: Author = serde_json::from_value(json!({
            "authorId": "1741101",
            "name": "Yoshua Bengio",
            "hIndex": 200,
            "citationCount": 500000,
            "paperCount": 1000,
            "url": "https://www.semanticscholar.org/author/1741101",
            "affiliations": ["Mila", "Universite de Montreal"],
            "aliases": ["Y. Bengio"],
        }))
        .unwrap();
        assert_eq!(a.author_id, "1741101");
        assert_eq!(a.name, Some("Yoshua Bengio".into()));
        assert_eq!(a.h_index, Some(200));
        assert_eq!(a.paper_count, Some(1000));
        assert_eq!(a.affiliations.as_ref().unwrap().len(), 2);
        let re = serde_json::to_value(&a).unwrap();
        assert_eq!(re["authorId"], "1741101");
    }

    #[test]
    fn author_minimal() {
        let a: Author = serde_json::from_value(json!({"authorId": "1"})).unwrap();
        assert_eq!(a.author_id, "1");
        assert!(a.name.is_none());
        assert!(a.h_index.is_none());
    }

    #[test]
    fn citation_edge_roundtrip() {
        let c: CitationEdge = serde_json::from_value(json!({
            "citingPaper": {"paperId": "p1", "title": "Paper One"},
            "contexts": ["as shown in [1]"],
            "intents": ["background"],
            "isInfluential": true,
        }))
        .unwrap();
        assert!(c.paper.is_some());
        assert_eq!(c.paper.as_ref().unwrap().paper_id, "p1");
        assert_eq!(c.is_influential, Some(true));
        assert_eq!(c.contexts.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn citation_edge_cited_paper() {
        let c: CitationEdge = serde_json::from_value(json!({
            "citedPaper": {"paperId": "p2", "title": "Paper Two"},
        }))
        .unwrap();
        assert!(c.paper.is_some());
        assert_eq!(c.paper.as_ref().unwrap().paper_id, "p2");
    }

    #[test]
    fn search_response_roundtrip() {
        let s: SearchResponse = serde_json::from_value(json!({
            "total": 1000,
            "offset": 0,
            "next": 10,
            "data": [{"paperId": "p1"}, {"paperId": "p2"}],
        }))
        .unwrap();
        assert_eq!(s.total, Some(1000));
        assert_eq!(s.data.len(), 2);
        assert_eq!(s.next, Some(10));
    }

    #[test]
    fn search_response_empty() {
        let s: SearchResponse = serde_json::from_value(json!({
            "total": 0,
            "data": [],
        }))
        .unwrap();
        assert_eq!(s.total, Some(0));
        assert!(s.data.is_empty());
    }

    #[test]
    fn citation_list_response_roundtrip() {
        let c: CitationListResponse = serde_json::from_value(json!({
            "offset": 0,
            "next": 100,
            "data": [{"citingPaper": {"paperId": "p1"}}],
        }))
        .unwrap();
        assert_eq!(c.data.len(), 1);
        assert_eq!(c.next, Some(100));
    }

    #[test]
    fn author_papers_response_roundtrip() {
        let a: AuthorPapersResponse = serde_json::from_value(json!({
            "offset": 0,
            "data": [{"paperId": "p1"}, {"paperId": "p2"}],
        }))
        .unwrap();
        assert_eq!(a.data.len(), 2);
    }

    #[test]
    fn recommendations_response_roundtrip() {
        let r: RecommendationsResponse = serde_json::from_value(json!({
            "recommendedPapers": [
                {"paperId": "r1", "title": "Rec 1"},
                {"paperId": "r2", "title": "Rec 2"},
            ],
        }))
        .unwrap();
        assert_eq!(r.recommended_papers.len(), 2);
    }

    #[test]
    fn recommendations_response_empty() {
        let r: RecommendationsResponse = serde_json::from_value(json!({
            "recommendedPapers": [],
        }))
        .unwrap();
        assert!(r.recommended_papers.is_empty());
    }

    #[test]
    fn api_error_response_with_error() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": "Bad Request",
            "message": "Invalid paper ID",
        }))
        .unwrap();
        assert_eq!(e.error, Some("Bad Request".into()));
        assert_eq!(e.message, Some("Invalid paper ID".into()));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.error.is_none());
        assert!(e.message.is_none());
    }

    #[test]
    fn api_error_response_message_only() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "Not Found",
        }))
        .unwrap();
        assert!(e.error.is_none());
        assert_eq!(e.message, Some("Not Found".into()));
    }

    #[test]
    fn paper_with_external_ids() {
        let p: Paper = serde_json::from_value(json!({
            "paperId": "p1",
            "externalIds": {"DOI": "10.1234/test", "ArXiv": "1706.03762"},
        }))
        .unwrap();
        assert!(p.external_ids.is_some());
        let ids = p.external_ids.unwrap();
        assert_eq!(ids["DOI"], "10.1234/test");
    }

    #[test]
    fn paper_with_journal() {
        let p: Paper = serde_json::from_value(json!({
            "paperId": "p1",
            "journal": {"name": "Nature", "volume": "42"},
        }))
        .unwrap();
        assert!(p.journal.is_some());
    }

    #[test]
    fn paper_with_tldr() {
        let p: Paper = serde_json::from_value(json!({
            "paperId": "p1",
            "tldr": {"model": "tldr@v2", "text": "This paper is about..."},
        }))
        .unwrap();
        assert!(p.tldr.is_some());
        assert_eq!(p.tldr.unwrap()["text"], "This paper is about...");
    }

    #[test]
    fn paper_serialization_preserves_camel_case() {
        let p: Paper = serde_json::from_value(json!({
            "paperId": "test",
            "citationCount": 100,
            "isOpenAccess": false,
        }))
        .unwrap();
        let v = serde_json::to_value(&p).unwrap();
        assert!(v.get("paperId").is_some());
        assert!(v.get("citationCount").is_some());
        assert!(v.get("isOpenAccess").is_some());
    }

    #[test]
    fn author_with_homepage() {
        let a: Author = serde_json::from_value(json!({
            "authorId": "1",
            "homepage": "https://example.com",
        }))
        .unwrap();
        assert_eq!(a.homepage, Some("https://example.com".into()));
    }

    #[test]
    fn paper_with_publication_date() {
        let p: Paper = serde_json::from_value(json!({
            "paperId": "p1",
            "publicationDate": "2023-01-15",
        }))
        .unwrap();
        assert_eq!(p.publication_date, Some("2023-01-15".into()));
    }
}
