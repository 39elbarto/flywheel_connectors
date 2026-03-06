//! arXiv API types.

use serde::{Deserialize, Serialize};

/// Parsed arXiv paper from Atom feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArxivPaper {
    pub arxiv_id: String,
    pub title: String,
    pub summary: String,
    pub authors: Vec<String>,
    pub published: String,
    pub updated: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_category: Option<String>,
    pub categories: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdf_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doi: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub journal_ref: Option<String>,
}

/// Semantic Scholar paper result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScholarPaper {
    #[serde(rename = "paperId")]
    pub paper_id: Option<String>,
    pub title: Option<String>,
    #[serde(rename = "abstract")]
    pub abstract_text: Option<String>,
    pub year: Option<i64>,
    #[serde(rename = "citationCount")]
    pub citation_count: Option<i64>,
    #[serde(rename = "externalIds")]
    pub external_ids: Option<serde_json::Value>,
    pub url: Option<String>,
    pub authors: Option<Vec<ScholarAuthorRef>>,
}

/// Semantic Scholar author reference (lightweight, in paper results).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScholarAuthorRef {
    #[serde(rename = "authorId")]
    pub author_id: Option<String>,
    pub name: Option<String>,
}

/// Semantic Scholar search response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScholarSearchResponse {
    pub total: Option<i64>,
    pub offset: Option<i64>,
    pub data: Option<Vec<ScholarPaper>>,
}

/// Semantic Scholar citation/reference item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScholarCitationItem {
    #[serde(rename = "citingPaper", alias = "citedPaper")]
    pub paper: Option<ScholarPaper>,
}

/// Semantic Scholar citations response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScholarCitationsResponse {
    pub offset: Option<i64>,
    pub data: Option<Vec<ScholarCitationItem>>,
}

/// Semantic Scholar author search result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScholarAuthor {
    #[serde(rename = "authorId")]
    pub author_id: Option<String>,
    pub name: Option<String>,
    #[serde(rename = "paperCount")]
    pub paper_count: Option<i64>,
    #[serde(rename = "citationCount")]
    pub citation_count: Option<i64>,
    #[serde(rename = "hIndex")]
    pub h_index: Option<i64>,
    pub url: Option<String>,
    pub papers: Option<Vec<ScholarPaper>>,
}

/// Semantic Scholar author search response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScholarAuthorSearchResponse {
    pub total: Option<i64>,
    pub data: Option<Vec<ScholarAuthor>>,
}

/// Semantic Scholar API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ScholarErrorResponse {
    pub error: Option<String>,
    pub message: Option<String>,
}

/// arXiv category definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArxivCategory {
    pub id: String,
    pub name: String,
    pub group: String,
}

/// Static list of core arXiv categories.
pub fn arxiv_categories() -> Vec<ArxivCategory> {
    vec![
        // Computer Science
        cat("cs.AI", "Artificial Intelligence", "cs"),
        cat("cs.CL", "Computation and Language", "cs"),
        cat("cs.CC", "Computational Complexity", "cs"),
        cat("cs.CE", "Computational Engineering", "cs"),
        cat("cs.CG", "Computational Geometry", "cs"),
        cat("cs.GT", "Computer Science and Game Theory", "cs"),
        cat("cs.CV", "Computer Vision and Pattern Recognition", "cs"),
        cat("cs.CY", "Computers and Society", "cs"),
        cat("cs.CR", "Cryptography and Security", "cs"),
        cat("cs.DS", "Data Structures and Algorithms", "cs"),
        cat("cs.DB", "Databases", "cs"),
        cat("cs.DL", "Digital Libraries", "cs"),
        cat("cs.DM", "Discrete Mathematics", "cs"),
        cat("cs.DC", "Distributed, Parallel, and Cluster Computing", "cs"),
        cat("cs.ET", "Emerging Technologies", "cs"),
        cat("cs.FL", "Formal Languages and Automata Theory", "cs"),
        cat("cs.GL", "General Literature", "cs"),
        cat("cs.GR", "Graphics", "cs"),
        cat("cs.AR", "Hardware Architecture", "cs"),
        cat("cs.HC", "Human-Computer Interaction", "cs"),
        cat("cs.IR", "Information Retrieval", "cs"),
        cat("cs.IT", "Information Theory", "cs"),
        cat("cs.LG", "Machine Learning", "cs"),
        cat("cs.LO", "Logic in Computer Science", "cs"),
        cat("cs.MA", "Multiagent Systems", "cs"),
        cat("cs.MM", "Multimedia", "cs"),
        cat("cs.NI", "Networking and Internet Architecture", "cs"),
        cat("cs.NE", "Neural and Evolutionary Computing", "cs"),
        cat("cs.NA", "Numerical Analysis", "cs"),
        cat("cs.OS", "Operating Systems", "cs"),
        cat("cs.OH", "Other", "cs"),
        cat("cs.PF", "Performance", "cs"),
        cat("cs.PL", "Programming Languages", "cs"),
        cat("cs.RO", "Robotics", "cs"),
        cat("cs.SI", "Social and Information Networks", "cs"),
        cat("cs.SE", "Software Engineering", "cs"),
        cat("cs.SD", "Sound", "cs"),
        cat("cs.SC", "Symbolic Computation", "cs"),
        cat("cs.SY", "Systems and Control", "cs"),
        // Math
        cat("math.AG", "Algebraic Geometry", "math"),
        cat("math.AT", "Algebraic Topology", "math"),
        cat("math.AP", "Analysis of PDEs", "math"),
        cat("math.CT", "Category Theory", "math"),
        cat("math.CA", "Classical Analysis and ODEs", "math"),
        cat("math.CO", "Combinatorics", "math"),
        cat("math.AC", "Commutative Algebra", "math"),
        cat("math.CV", "Complex Variables", "math"),
        cat("math.DG", "Differential Geometry", "math"),
        cat("math.DS", "Dynamical Systems", "math"),
        cat("math.FA", "Functional Analysis", "math"),
        cat("math.GM", "General Mathematics", "math"),
        cat("math.GN", "General Topology", "math"),
        cat("math.GT", "Geometric Topology", "math"),
        cat("math.GR", "Group Theory", "math"),
        cat("math.HO", "History and Overview", "math"),
        cat("math.IT", "Information Theory", "math"),
        cat("math.KT", "K-Theory and Homology", "math"),
        cat("math.LO", "Logic", "math"),
        cat("math.MP", "Mathematical Physics", "math"),
        cat("math.MG", "Metric Geometry", "math"),
        cat("math.NT", "Number Theory", "math"),
        cat("math.NA", "Numerical Analysis", "math"),
        cat("math.OA", "Operator Algebras", "math"),
        cat("math.OC", "Optimization and Control", "math"),
        cat("math.PR", "Probability", "math"),
        cat("math.QA", "Quantum Algebra", "math"),
        cat("math.RT", "Representation Theory", "math"),
        cat("math.RA", "Rings and Algebras", "math"),
        cat("math.SP", "Spectral Theory", "math"),
        cat("math.ST", "Statistics Theory", "math"),
        cat("math.SG", "Symplectic Geometry", "math"),
        // Physics
        cat("astro-ph", "Astrophysics", "physics"),
        cat("cond-mat", "Condensed Matter", "physics"),
        cat("gr-qc", "General Relativity and Quantum Cosmology", "physics"),
        cat("hep-ex", "High Energy Physics - Experiment", "physics"),
        cat("hep-lat", "High Energy Physics - Lattice", "physics"),
        cat("hep-ph", "High Energy Physics - Phenomenology", "physics"),
        cat("hep-th", "High Energy Physics - Theory", "physics"),
        cat("math-ph", "Mathematical Physics", "physics"),
        cat("nlin", "Nonlinear Sciences", "physics"),
        cat("nucl-ex", "Nuclear Experiment", "physics"),
        cat("nucl-th", "Nuclear Theory", "physics"),
        cat("physics", "Physics", "physics"),
        cat("quant-ph", "Quantum Physics", "physics"),
        // Quantitative Biology
        cat("q-bio.BM", "Biomolecules", "q-bio"),
        cat("q-bio.CB", "Cell Behavior", "q-bio"),
        cat("q-bio.GN", "Genomics", "q-bio"),
        cat("q-bio.MN", "Molecular Networks", "q-bio"),
        cat("q-bio.NC", "Neurons and Cognition", "q-bio"),
        cat("q-bio.OT", "Other Quantitative Biology", "q-bio"),
        cat("q-bio.PE", "Populations and Evolution", "q-bio"),
        cat("q-bio.QM", "Quantitative Methods", "q-bio"),
        cat("q-bio.SC", "Subcellular Processes", "q-bio"),
        cat("q-bio.TO", "Tissues and Organs", "q-bio"),
        // Quantitative Finance
        cat("q-fin.CP", "Computational Finance", "q-fin"),
        cat("q-fin.EC", "Economics", "q-fin"),
        cat("q-fin.GN", "General Finance", "q-fin"),
        cat("q-fin.MF", "Mathematical Finance", "q-fin"),
        cat("q-fin.PM", "Portfolio Management", "q-fin"),
        cat("q-fin.PR", "Pricing of Securities", "q-fin"),
        cat("q-fin.RM", "Risk Management", "q-fin"),
        cat("q-fin.ST", "Statistical Finance", "q-fin"),
        cat("q-fin.TR", "Trading and Market Microstructure", "q-fin"),
        // Statistics
        cat("stat.AP", "Applications", "stat"),
        cat("stat.CO", "Computation", "stat"),
        cat("stat.ME", "Methodology", "stat"),
        cat("stat.ML", "Machine Learning", "stat"),
        cat("stat.OT", "Other Statistics", "stat"),
        cat("stat.TH", "Statistics Theory", "stat"),
        // EESS
        cat("eess.AS", "Audio and Speech Processing", "eess"),
        cat("eess.IV", "Image and Video Processing", "eess"),
        cat("eess.SP", "Signal Processing", "eess"),
        cat("eess.SY", "Systems and Control", "eess"),
        // Economics
        cat("econ.EM", "Econometrics", "econ"),
        cat("econ.GN", "General Economics", "econ"),
        cat("econ.TH", "Theoretical Economics", "econ"),
    ]
}

fn cat(id: &str, name: &str, group: &str) -> ArxivCategory {
    ArxivCategory {
        id: id.to_string(),
        name: name.to_string(),
        group: group.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn arxiv_paper_roundtrip() {
        let p = ArxivPaper {
            arxiv_id: "2301.08745".into(),
            title: "Test Paper".into(),
            summary: "A summary".into(),
            authors: vec!["Alice".into(), "Bob".into()],
            published: "2023-01-20T00:00:00Z".into(),
            updated: "2023-01-21T00:00:00Z".into(),
            primary_category: Some("cs.AI".into()),
            categories: vec!["cs.AI".into(), "cs.LG".into()],
            pdf_url: Some("http://arxiv.org/pdf/2301.08745".into()),
            doi: Some("10.1234/test".into()),
            comment: None,
            journal_ref: None,
        };
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["arxiv_id"], "2301.08745");
        assert_eq!(v["authors"].as_array().unwrap().len(), 2);
        assert!(v.get("comment").is_none()); // skip_serializing_if
        let p2: ArxivPaper = serde_json::from_value(v).unwrap();
        assert_eq!(p2.title, "Test Paper");
    }

    #[test]
    fn arxiv_paper_minimal() {
        let p: ArxivPaper = serde_json::from_value(json!({
            "arxiv_id": "0000.0000",
            "title": "T",
            "summary": "S",
            "authors": [],
            "published": "",
            "updated": "",
            "categories": [],
        }))
        .unwrap();
        assert_eq!(p.arxiv_id, "0000.0000");
        assert!(p.primary_category.is_none());
        assert!(p.doi.is_none());
    }

    #[test]
    fn scholar_paper_roundtrip() {
        let p: ScholarPaper = serde_json::from_value(json!({
            "paperId": "abc123",
            "title": "Scholar Paper",
            "abstract": "An abstract",
            "year": 2023,
            "citationCount": 42,
            "externalIds": {"ArXiv": "2301.08745"},
            "url": "https://semanticscholar.org/paper/abc123",
            "authors": [{"authorId": "a1", "name": "Alice"}]
        }))
        .unwrap();
        assert_eq!(p.paper_id, Some("abc123".into()));
        assert_eq!(p.citation_count, Some(42));
        assert_eq!(p.authors.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn scholar_paper_minimal() {
        let p: ScholarPaper = serde_json::from_value(json!({})).unwrap();
        assert!(p.paper_id.is_none());
        assert!(p.title.is_none());
    }

    #[test]
    fn scholar_search_response_roundtrip() {
        let r: ScholarSearchResponse = serde_json::from_value(json!({
            "total": 100,
            "offset": 0,
            "data": [{"paperId": "p1", "title": "Test"}]
        }))
        .unwrap();
        assert_eq!(r.total, Some(100));
        assert_eq!(r.data.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn scholar_citation_item_citing() {
        let item: ScholarCitationItem = serde_json::from_value(json!({
            "citingPaper": {"paperId": "p1", "title": "Citing"}
        }))
        .unwrap();
        assert_eq!(item.paper.as_ref().unwrap().title, Some("Citing".into()));
    }

    #[test]
    fn scholar_citation_item_cited() {
        let item: ScholarCitationItem = serde_json::from_value(json!({
            "citedPaper": {"paperId": "p2", "title": "Referenced"}
        }))
        .unwrap();
        assert_eq!(
            item.paper.as_ref().unwrap().title,
            Some("Referenced".into())
        );
    }

    #[test]
    fn scholar_author_roundtrip() {
        let a: ScholarAuthor = serde_json::from_value(json!({
            "authorId": "123",
            "name": "Alice Smith",
            "paperCount": 50,
            "citationCount": 1000,
            "hIndex": 25,
            "url": "https://semanticscholar.org/author/123",
            "papers": []
        }))
        .unwrap();
        assert_eq!(a.name, Some("Alice Smith".into()));
        assert_eq!(a.h_index, Some(25));
    }

    #[test]
    fn scholar_author_search_response() {
        let r: ScholarAuthorSearchResponse = serde_json::from_value(json!({
            "total": 3,
            "data": [
                {"authorId": "1", "name": "Alice"},
                {"authorId": "2", "name": "Bob"}
            ]
        }))
        .unwrap();
        assert_eq!(r.total, Some(3));
        assert_eq!(r.data.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn scholar_error_response() {
        let e: ScholarErrorResponse = serde_json::from_value(json!({
            "error": "Not Found",
            "message": "Paper not found"
        }))
        .unwrap();
        assert_eq!(e.error, Some("Not Found".into()));
        assert_eq!(e.message, Some("Paper not found".into()));
    }

    #[test]
    fn scholar_error_response_empty() {
        let e: ScholarErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.error.is_none());
        assert!(e.message.is_none());
    }

    #[test]
    fn arxiv_categories_non_empty() {
        let cats = arxiv_categories();
        assert!(cats.len() > 100);
    }

    #[test]
    fn arxiv_categories_have_cs_ai() {
        let cats = arxiv_categories();
        assert!(cats.iter().any(|c| c.id == "cs.AI"));
    }

    #[test]
    fn arxiv_categories_all_have_group() {
        let cats = arxiv_categories();
        for c in &cats {
            assert!(!c.group.is_empty(), "category {} has empty group", c.id);
        }
    }

    #[test]
    fn arxiv_categories_ids_unique() {
        let cats = arxiv_categories();
        let mut ids: Vec<&str> = cats.iter().map(|c| c.id.as_str()).collect();
        ids.sort_unstable();
        let len_before = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), len_before, "duplicate category IDs");
    }

    #[test]
    fn arxiv_categories_filter_by_group() {
        let cats = arxiv_categories();
        let cs_cats = cats.iter().filter(|c| c.group == "cs").count();
        assert!(cs_cats > 30);
        let math_cats = cats.iter().filter(|c| c.group == "math").count();
        assert!(math_cats > 20);
    }

    #[test]
    fn arxiv_category_serialize() {
        let c = cat("cs.AI", "Artificial Intelligence", "cs");
        let v = serde_json::to_value(&c).unwrap();
        assert_eq!(v["id"], "cs.AI");
        assert_eq!(v["name"], "Artificial Intelligence");
        assert_eq!(v["group"], "cs");
    }

    #[test]
    fn arxiv_category_deserialize() {
        let c: ArxivCategory = serde_json::from_value(json!({
            "id": "math.CO",
            "name": "Combinatorics",
            "group": "math"
        }))
        .unwrap();
        assert_eq!(c.id, "math.CO");
    }

    // ---- ArxivPaper additional tests ----

    #[test]
    fn arxiv_paper_clone_and_drop() {
        let original = ArxivPaper {
            arxiv_id: "2301.00000".into(),
            title: "Clone Test".into(),
            summary: "S".into(),
            authors: vec!["A".into()],
            published: "2023-01-01".into(),
            updated: "2023-01-02".into(),
            primary_category: Some("cs.AI".into()),
            categories: vec!["cs.AI".into()],
            pdf_url: None,
            doi: None,
            comment: None,
            journal_ref: None,
        };
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.arxiv_id, "2301.00000");
        assert_eq!(cloned.title, "Clone Test");
    }

    #[test]
    fn arxiv_paper_debug() {
        let p = ArxivPaper {
            arxiv_id: "debug_test".into(),
            title: "T".into(),
            summary: "S".into(),
            authors: vec![],
            published: String::new(),
            updated: String::new(),
            primary_category: None,
            categories: vec![],
            pdf_url: None,
            doi: None,
            comment: None,
            journal_ref: None,
        };
        let dbg = format!("{p:?}");
        assert!(dbg.contains("ArxivPaper"));
        assert!(dbg.contains("debug_test"));
    }

    #[test]
    fn arxiv_paper_with_all_optional_fields() {
        let p = ArxivPaper {
            arxiv_id: "2301.99999".into(),
            title: "Full Paper".into(),
            summary: "All fields".into(),
            authors: vec!["Alice".into(), "Bob".into()],
            published: "2023-01-01T00:00:00Z".into(),
            updated: "2023-01-02T00:00:00Z".into(),
            primary_category: Some("cs.CL".into()),
            categories: vec!["cs.CL".into(), "cs.AI".into()],
            pdf_url: Some("https://arxiv.org/pdf/2301.99999".into()),
            doi: Some("10.1234/full".into()),
            comment: Some("10 pages, 5 figures".into()),
            journal_ref: Some("Nature 2023".into()),
        };
        let v = serde_json::to_value(&p).unwrap();
        assert!(v.get("comment").is_some());
        assert!(v.get("journal_ref").is_some());
        assert_eq!(v["doi"], "10.1234/full");
    }

    // ---- ScholarPaper additional tests ----

    #[test]
    fn scholar_paper_clone_and_drop() {
        let original: ScholarPaper = serde_json::from_value(json!({
            "paperId": "clone_test",
            "title": "T"
        }))
        .unwrap();
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.paper_id, Some("clone_test".into()));
    }

    #[test]
    fn scholar_paper_debug() {
        let p: ScholarPaper = serde_json::from_value(json!({"paperId": "dbg"})).unwrap();
        let dbg = format!("{p:?}");
        assert!(dbg.contains("ScholarPaper"));
    }

    // ---- ScholarAuthorRef additional tests ----

    #[test]
    fn scholar_author_ref_clone_and_drop() {
        let original = ScholarAuthorRef {
            author_id: Some("a1".into()),
            name: Some("Test".into()),
        };
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.author_id, Some("a1".into()));
    }

    #[test]
    fn scholar_author_ref_debug() {
        let a = ScholarAuthorRef {
            author_id: None,
            name: None,
        };
        let dbg = format!("{a:?}");
        assert!(dbg.contains("ScholarAuthorRef"));
    }

    // ---- ScholarSearchResponse additional tests ----

    #[test]
    fn scholar_search_response_minimal() {
        let r: ScholarSearchResponse = serde_json::from_value(json!({})).unwrap();
        assert!(r.total.is_none());
        assert!(r.offset.is_none());
        assert!(r.data.is_none());
    }

    #[test]
    fn scholar_search_response_clone_and_drop() {
        let original: ScholarSearchResponse = serde_json::from_value(json!({
            "total": 5,
            "data": []
        }))
        .unwrap();
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.total, Some(5));
    }

    // ---- ScholarCitationsResponse additional tests ----

    #[test]
    fn scholar_citations_response_roundtrip() {
        let r: ScholarCitationsResponse = serde_json::from_value(json!({
            "offset": 0,
            "data": [{"citingPaper": {"paperId": "p1"}}]
        }))
        .unwrap();
        assert_eq!(r.data.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn scholar_citations_response_empty() {
        let r: ScholarCitationsResponse = serde_json::from_value(json!({})).unwrap();
        assert!(r.offset.is_none());
        assert!(r.data.is_none());
    }

    // ---- ScholarAuthorSearchResponse additional tests ----

    #[test]
    fn scholar_author_search_response_minimal() {
        let r: ScholarAuthorSearchResponse = serde_json::from_value(json!({})).unwrap();
        assert!(r.total.is_none());
        assert!(r.data.is_none());
    }

    // ---- ArxivCategory additional tests ----

    #[test]
    fn arxiv_category_clone_and_drop() {
        let original = cat("cs.AI", "Artificial Intelligence", "cs");
        let cloned = original.clone();
        drop(original);
        assert_eq!(cloned.id, "cs.AI");
        assert_eq!(cloned.name, "Artificial Intelligence");
        assert_eq!(cloned.group, "cs");
    }

    #[test]
    fn arxiv_category_debug() {
        let c = cat("stat.ML", "Machine Learning", "stat");
        let dbg = format!("{c:?}");
        assert!(dbg.contains("ArxivCategory"));
        assert!(dbg.contains("stat.ML"));
    }

    #[test]
    fn arxiv_categories_has_physics_groups() {
        let cats = arxiv_categories();
        let physics_cats = cats.iter().filter(|c| c.group == "physics").count();
        assert!(physics_cats > 5);
    }

    #[test]
    fn arxiv_categories_has_econ_group() {
        let cats = arxiv_categories();
        let econ_cats = cats.iter().filter(|c| c.group == "econ").count();
        assert!(econ_cats >= 3);
    }

    #[test]
    fn arxiv_categories_has_stat_group() {
        let cats = arxiv_categories();
        let stat_cats = cats.iter().filter(|c| c.group == "stat").count();
        assert!(stat_cats >= 5);
    }
}
