//! Simple XML tag extraction for arXiv Atom feeds.
//!
//! We avoid full XML parser dependencies and instead do lightweight
//! string-based extraction of the Atom elements we need.

use crate::types::ArxivPaper;

/// Extract the text content of the first occurrence of a given XML tag.
/// Handles tags that may have attributes (e.g., `<link href="..."/>`).
pub fn extract_tag<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let start = xml.find(&open)?;
    let after_open = &xml[start..];
    let gt_pos = after_open.find('>')?;
    let content_start = start + gt_pos + 1;
    let end = xml[content_start..].find(&close)? + content_start;
    Some(&xml[content_start..end])
}

/// Extract the `href` attribute from the first `<link>` tag matching a condition.
pub fn extract_link_href<'a>(xml: &'a str, rel: Option<&str>) -> Option<&'a str> {
    let mut search_from = 0;
    while let Some(pos) = xml[search_from..].find("<link") {
        let abs_pos = search_from + pos;
        let tag_end = xml[abs_pos..].find('>')?;
        let tag = &xml[abs_pos..=abs_pos + tag_end];

        let matches = if let Some(rel_val) = rel {
            tag.contains(&format!("rel=\"{rel_val}\""))
        } else {
            !tag.contains("rel=")
        };

        if matches {
            if let Some(href_start) = tag.find("href=\"") {
                let val_start = href_start + 6;
                let val_end = tag[val_start..].find('"')? + val_start;
                return Some(&tag[val_start..val_end]);
            }
        }
        search_from = abs_pos + tag_end + 1;
    }
    None
}

/// Extract all `<name>` values from `<author>` blocks.
pub fn extract_authors(xml: &str) -> Vec<String> {
    let mut authors = Vec::new();
    let mut search_from = 0;
    while let Some(pos) = xml[search_from..].find("<author>") {
        let abs_pos = search_from + pos;
        if let Some(end) = xml[abs_pos..].find("</author>") {
            let author_block = &xml[abs_pos..abs_pos + end];
            if let Some(name) = extract_tag(author_block, "name") {
                authors.push(name.trim().to_string());
            }
            search_from = abs_pos + end + 9;
        } else {
            break;
        }
    }
    authors
}

/// Extract the primary arXiv category from `<arxiv:primary_category>`.
pub fn extract_primary_category(xml: &str) -> Option<String> {
    let tag = "arxiv:primary_category";
    let open = format!("<{tag}");
    let start = xml.find(&open)?;
    let after_open = &xml[start..];
    let gt_pos = after_open.find('>')?;
    let tag_str = &after_open[..=gt_pos];

    if let Some(term_start) = tag_str.find("term=\"") {
        let val_start = term_start + 6;
        let val_end = tag_str[val_start..].find('"')? + val_start;
        return Some(tag_str[val_start..val_end].to_string());
    }
    None
}

/// Extract all category terms.
pub fn extract_categories(xml: &str) -> Vec<String> {
    let mut cats = Vec::new();
    let mut search_from = 0;
    while let Some(pos) = xml[search_from..].find("<category") {
        let abs_pos = search_from + pos;
        if let Some(gt) = xml[abs_pos..].find('>') {
            let tag_str = &xml[abs_pos..=abs_pos + gt];
            if let Some(term_start) = tag_str.find("term=\"") {
                let val_start = term_start + 6;
                if let Some(val_end) = tag_str[val_start..].find('"') {
                    cats.push(tag_str[val_start..val_start + val_end].to_string());
                }
            }
            search_from = abs_pos + gt + 1;
        } else {
            break;
        }
    }
    cats
}

/// Extract the arXiv ID from an entry's `<id>` tag.
/// The ID URL looks like `http://arxiv.org/abs/2301.08745v2`.
pub fn extract_arxiv_id(id_url: &str) -> String {
    id_url
        .rsplit('/')
        .next()
        .unwrap_or(id_url)
        .to_string()
}

/// Extract the `<opensearch:totalResults>` value.
pub fn extract_total_results(xml: &str) -> Option<i64> {
    extract_tag(xml, "opensearch:totalResults")
        .and_then(|s| s.trim().parse().ok())
}

/// Parse Atom XML feed into a vector of `ArxivPaper` structs.
pub fn parse_atom_entries(xml: &str) -> Vec<ArxivPaper> {
    let mut papers = Vec::new();
    for entry in xml.split("<entry>").skip(1) {
        if let Some(end) = entry.find("</entry>") {
            let entry = &entry[..end];
            let id_url = extract_tag(entry, "id").unwrap_or_default();
            let arxiv_id = extract_arxiv_id(id_url.trim());
            let title = extract_tag(entry, "title")
                .unwrap_or_default()
                .trim()
                .replace('\n', " ");
            let summary = extract_tag(entry, "summary")
                .unwrap_or_default()
                .trim()
                .replace('\n', " ");
            let published = extract_tag(entry, "published")
                .unwrap_or_default()
                .trim()
                .to_string();
            let updated = extract_tag(entry, "updated")
                .unwrap_or_default()
                .trim()
                .to_string();
            let authors = extract_authors(entry);
            let primary_category = extract_primary_category(entry);
            let categories = extract_categories(entry);
            let pdf_url = extract_link_href(entry, Some("related"))
                .or_else(|| {
                    // Fallback: look for a link containing "pdf"
                    let mut search = 0;
                    while let Some(pos) = entry[search..].find("<link") {
                        let abs = search + pos;
                        if let Some(gt) = entry[abs..].find('>') {
                            let tag = &entry[abs..=abs + gt];
                            if tag.contains("pdf") {
                                if let Some(hs) = tag.find("href=\"") {
                                    let vs = hs + 6;
                                    if let Some(ve) = tag[vs..].find('"') {
                                        return Some(&entry[abs + vs..abs + vs + ve]);
                                    }
                                }
                            }
                            search = abs + gt + 1;
                        } else {
                            break;
                        }
                    }
                    None
                })
                .map(str::to_string);
            let doi = extract_tag(entry, "arxiv:doi").map(|s| s.trim().to_string());
            let comment = extract_tag(entry, "arxiv:comment").map(|s| s.trim().to_string());
            let journal_ref =
                extract_tag(entry, "arxiv:journal_ref").map(|s| s.trim().to_string());

            papers.push(ArxivPaper {
                arxiv_id,
                title,
                summary,
                authors,
                published,
                updated,
                primary_category,
                categories,
                pdf_url,
                doi,
                comment,
                journal_ref,
            });
        }
    }
    papers
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_ENTRY: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
<opensearch:totalResults>1</opensearch:totalResults>
<entry>
<id>http://arxiv.org/abs/1706.03762v7</id>
<title>Attention Is All You Need</title>
<summary>The dominant sequence transduction models are based on complex recurrent or convolutional neural networks.</summary>
<author><name>Ashish Vaswani</name></author>
<author><name>Noam Shazeer</name></author>
<author><name>Niki Parmar</name></author>
<published>2017-06-12T17:57:34Z</published>
<updated>2023-08-02T01:04:45Z</updated>
<arxiv:primary_category term="cs.CL" scheme="http://arxiv.org/schemas/atom"/>
<category term="cs.CL" scheme="http://arxiv.org/schemas/atom"/>
<category term="cs.LG" scheme="http://arxiv.org/schemas/atom"/>
<link href="http://arxiv.org/abs/1706.03762v7" rel="alternate" type="text/html"/>
<link title="pdf" href="http://arxiv.org/pdf/1706.03762v7" rel="related" type="application/pdf"/>
<arxiv:doi>10.48550/arXiv.1706.03762</arxiv:doi>
<arxiv:comment>15 pages, 5 figures</arxiv:comment>
</entry>
</feed>"#;

    #[test]
    fn extract_tag_basic() {
        assert_eq!(
            extract_tag("<title>Hello World</title>", "title"),
            Some("Hello World")
        );
    }

    #[test]
    fn extract_tag_with_attributes() {
        assert_eq!(
            extract_tag("<title lang=\"en\">Hello</title>", "title"),
            Some("Hello")
        );
    }

    #[test]
    fn extract_tag_missing() {
        assert_eq!(extract_tag("<foo>bar</foo>", "title"), None);
    }

    #[test]
    fn extract_tag_empty() {
        assert_eq!(extract_tag("<title></title>", "title"), Some(""));
    }

    #[test]
    fn extract_tag_nested_content() {
        let xml = "<summary>Line one\nLine two</summary>";
        let result = extract_tag(xml, "summary").unwrap();
        assert!(result.contains("Line one"));
        assert!(result.contains("Line two"));
    }

    #[test]
    fn extract_authors_multiple() {
        let xml = r"<author><name>Alice</name></author><author><name>Bob</name></author>";
        let authors = extract_authors(xml);
        assert_eq!(authors, vec!["Alice", "Bob"]);
    }

    #[test]
    fn extract_authors_none() {
        assert!(extract_authors("<foo>bar</foo>").is_empty());
    }

    #[test]
    fn extract_authors_with_whitespace() {
        let xml = r"<author><name>  Alice Smith  </name></author>";
        let authors = extract_authors(xml);
        assert_eq!(authors, vec!["Alice Smith"]);
    }

    #[test]
    fn extract_primary_category_present() {
        let xml = r#"<arxiv:primary_category term="cs.AI" scheme="http://arxiv.org/schemas/atom"/>"#;
        assert_eq!(extract_primary_category(xml), Some("cs.AI".into()));
    }

    #[test]
    fn extract_primary_category_missing() {
        assert_eq!(extract_primary_category("<foo/>"), None);
    }

    #[test]
    fn extract_categories_multiple() {
        let xml = r#"<category term="cs.CL"/><category term="cs.LG"/>"#;
        let cats = extract_categories(xml);
        assert_eq!(cats, vec!["cs.CL", "cs.LG"]);
    }

    #[test]
    fn extract_categories_empty() {
        assert!(extract_categories("<foo/>").is_empty());
    }

    #[test]
    fn extract_arxiv_id_from_url() {
        assert_eq!(
            extract_arxiv_id("http://arxiv.org/abs/1706.03762v7"),
            "1706.03762v7"
        );
    }

    #[test]
    fn extract_arxiv_id_bare() {
        assert_eq!(extract_arxiv_id("2301.08745"), "2301.08745");
    }

    #[test]
    fn extract_total_results_present() {
        let xml = "<opensearch:totalResults>42</opensearch:totalResults>";
        assert_eq!(extract_total_results(xml), Some(42));
    }

    #[test]
    fn extract_total_results_missing() {
        assert_eq!(extract_total_results("<foo/>"), None);
    }

    #[test]
    fn extract_total_results_non_numeric() {
        let xml = "<opensearch:totalResults>abc</opensearch:totalResults>";
        assert_eq!(extract_total_results(xml), None);
    }

    #[test]
    fn parse_atom_entries_sample() {
        let papers = parse_atom_entries(SAMPLE_ENTRY);
        assert_eq!(papers.len(), 1);
        let p = &papers[0];
        assert_eq!(p.arxiv_id, "1706.03762v7");
        assert_eq!(p.title, "Attention Is All You Need");
        assert!(p.summary.contains("dominant sequence"));
        assert_eq!(p.authors.len(), 3);
        assert_eq!(p.authors[0], "Ashish Vaswani");
        assert_eq!(p.published, "2017-06-12T17:57:34Z");
        assert_eq!(p.primary_category, Some("cs.CL".into()));
        assert_eq!(p.categories.len(), 2);
        assert!(p.pdf_url.is_some());
        assert_eq!(p.doi, Some("10.48550/arXiv.1706.03762".into()));
        assert_eq!(p.comment, Some("15 pages, 5 figures".into()));
    }

    #[test]
    fn parse_atom_entries_empty_feed() {
        let xml = r#"<?xml version="1.0"?><feed></feed>"#;
        assert!(parse_atom_entries(xml).is_empty());
    }

    #[test]
    fn parse_atom_entries_multiple() {
        let xml = r"<feed>
<entry><id>http://arxiv.org/abs/1111.1111</id><title>Paper A</title><summary>Summary A</summary><published>2020-01-01T00:00:00Z</published><updated>2020-01-01T00:00:00Z</updated></entry>
<entry><id>http://arxiv.org/abs/2222.2222</id><title>Paper B</title><summary>Summary B</summary><published>2021-02-02T00:00:00Z</published><updated>2021-02-02T00:00:00Z</updated></entry>
</feed>";
        let papers = parse_atom_entries(xml);
        assert_eq!(papers.len(), 2);
        assert_eq!(papers[0].arxiv_id, "1111.1111");
        assert_eq!(papers[1].title, "Paper B");
    }

    #[test]
    fn parse_atom_entries_multiline_title() {
        let xml = r"<feed><entry><id>http://arxiv.org/abs/0000.0000</id><title>Multi
  Line Title</title><summary>ok</summary><published>2020-01-01T00:00:00Z</published><updated>2020-01-01T00:00:00Z</updated></entry></feed>";
        let papers = parse_atom_entries(xml);
        assert_eq!(papers.len(), 1);
        assert_eq!(papers[0].title, "Multi Line Title");
    }

    #[test]
    fn extract_link_href_alternate() {
        let xml = r#"<link href="http://arxiv.org/abs/1706.03762v7" rel="alternate" type="text/html"/>"#;
        assert_eq!(
            extract_link_href(xml, Some("alternate")),
            Some("http://arxiv.org/abs/1706.03762v7")
        );
    }

    #[test]
    fn extract_link_href_none() {
        assert_eq!(extract_link_href("<foo/>", Some("alternate")), None);
    }

    #[test]
    fn extract_doi_from_entry() {
        let xml = r"<arxiv:doi>10.1234/test</arxiv:doi>";
        assert_eq!(extract_tag(xml, "arxiv:doi"), Some("10.1234/test"));
    }

    #[test]
    fn extract_comment_from_entry() {
        let xml = r"<arxiv:comment>15 pages</arxiv:comment>";
        assert_eq!(extract_tag(xml, "arxiv:comment"), Some("15 pages"));
    }

    #[test]
    fn extract_journal_ref() {
        let xml = r"<arxiv:journal_ref>Nature 2023</arxiv:journal_ref>";
        assert_eq!(
            extract_tag(xml, "arxiv:journal_ref"),
            Some("Nature 2023")
        );
    }

    #[test]
    fn paper_missing_optional_fields() {
        let xml = r"<feed><entry><id>http://arxiv.org/abs/9999.9999</id><title>T</title><summary>S</summary><published>2024-01-01T00:00:00Z</published><updated>2024-01-01T00:00:00Z</updated></entry></feed>";
        let papers = parse_atom_entries(xml);
        assert_eq!(papers.len(), 1);
        let p = &papers[0];
        assert!(p.doi.is_none());
        assert!(p.comment.is_none());
        assert!(p.journal_ref.is_none());
        assert!(p.primary_category.is_none());
        assert!(p.pdf_url.is_none());
        assert!(p.authors.is_empty());
    }

    #[test]
    fn total_results_from_sample() {
        assert_eq!(extract_total_results(SAMPLE_ENTRY), Some(1));
    }
}
