#![no_main]
//! arXiv Atom-feed parser fuzz target.
//!
//! Exercises the connector's lightweight XML extraction boundary with both raw
//! bytes and structured Atom-like feeds. This keeps malformed input coverage
//! broad while giving libFuzzer valid entries that reach paper normalization.

use arbitrary::{Arbitrary, Unstructured};
use fcp_arxiv::xml_parser::{
    extract_authors, extract_categories, extract_link_href, extract_primary_category, extract_tag,
    extract_total_results, parse_atom_entries,
};
use libfuzzer_sys::fuzz_target;

const MAX_RAW_XML_BYTES: usize = 32 * 1024;
const MAX_FIELD_BYTES: usize = 512;
const MAX_ENTRIES: usize = 8;
const MAX_AUTHORS: usize = 16;
const MAX_CATEGORIES: usize = 16;

#[derive(Arbitrary, Debug)]
struct ArxivAtomFuzz<'a> {
    mode: u8,
    raw_xml: &'a [u8],
    total_results: Option<i64>,
    entries: Vec<EntryFuzz<'a>>,
}

#[derive(Arbitrary, Debug)]
struct EntryFuzz<'a> {
    id: Option<&'a [u8]>,
    title: &'a [u8],
    summary: &'a [u8],
    published: Option<&'a [u8]>,
    updated: Option<&'a [u8]>,
    authors: Vec<&'a [u8]>,
    primary_category: Option<&'a [u8]>,
    categories: Vec<&'a [u8]>,
    pdf_url: Option<&'a [u8]>,
    doi: Option<&'a [u8]>,
    comment: Option<&'a [u8]>,
    journal_ref: Option<&'a [u8]>,
}

fn bounded(bytes: &[u8], max: usize) -> &[u8] {
    &bytes[..bytes.len().min(max)]
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bounded(bytes, MAX_FIELD_BYTES))
        .chars()
        .filter(|ch| !ch.is_control())
        .take(MAX_FIELD_BYTES)
        .collect()
}

fn xml_text(bytes: &[u8]) -> String {
    text(bytes)
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn xml_attr(bytes: &[u8]) -> String {
    xml_text(bytes).replace('"', "&quot;")
}

fn optional_text(value: Option<&[u8]>) -> String {
    value.map_or_else(String::new, xml_text)
}

fn structured_feed(input: &ArxivAtomFuzz<'_>) -> (String, usize) {
    let mut xml = String::from(r#"<?xml version="1.0" encoding="UTF-8"?><feed>"#);
    if let Some(total) = input.total_results {
        xml.push_str("<opensearch:totalResults>");
        xml.push_str(&total.to_string());
        xml.push_str("</opensearch:totalResults>");
    }

    let expected_entries = input.entries.len().min(MAX_ENTRIES);
    for entry in input.entries.iter().take(MAX_ENTRIES) {
        xml.push_str("<entry>");
        xml.push_str("<id>http://arxiv.org/abs/");
        xml.push_str(&optional_text(entry.id));
        xml.push_str("</id>");
        xml.push_str("<title>");
        xml.push_str(&xml_text(entry.title));
        xml.push_str("</title>");
        xml.push_str("<summary>");
        xml.push_str(&xml_text(entry.summary));
        xml.push_str("</summary>");
        xml.push_str("<published>");
        xml.push_str(&optional_text(entry.published));
        xml.push_str("</published>");
        xml.push_str("<updated>");
        xml.push_str(&optional_text(entry.updated));
        xml.push_str("</updated>");

        for author in entry.authors.iter().take(MAX_AUTHORS) {
            xml.push_str("<author><name>");
            xml.push_str(&xml_text(author));
            xml.push_str("</name></author>");
        }

        if let Some(primary) = entry.primary_category {
            xml.push_str(r#"<arxiv:primary_category term=""#);
            xml.push_str(&xml_attr(primary));
            xml.push_str(r#"" scheme="http://arxiv.org/schemas/atom"/>"#);
        }

        for category in entry.categories.iter().take(MAX_CATEGORIES) {
            xml.push_str(r#"<category term=""#);
            xml.push_str(&xml_attr(category));
            xml.push_str(r#"" scheme="http://arxiv.org/schemas/atom"/>"#);
        }

        if let Some(pdf_url) = entry.pdf_url {
            xml.push_str(r#"<link title="pdf" href=""#);
            xml.push_str(&xml_attr(pdf_url));
            xml.push_str(r#"" rel="related" type="application/pdf"/>"#);
        }
        if let Some(doi) = entry.doi {
            xml.push_str("<arxiv:doi>");
            xml.push_str(&xml_text(doi));
            xml.push_str("</arxiv:doi>");
        }
        if let Some(comment) = entry.comment {
            xml.push_str("<arxiv:comment>");
            xml.push_str(&xml_text(comment));
            xml.push_str("</arxiv:comment>");
        }
        if let Some(journal_ref) = entry.journal_ref {
            xml.push_str("<arxiv:journal_ref>");
            xml.push_str(&xml_text(journal_ref));
            xml.push_str("</arxiv:journal_ref>");
        }
        xml.push_str("</entry>");
    }
    xml.push_str("</feed>");
    (xml, expected_entries)
}

fn exercise_xml(xml: &str) {
    let papers = parse_atom_entries(xml);
    for paper in papers {
        assert!(!paper.arxiv_id.contains('/'));
        assert_eq!(
            paper.title,
            paper.title.split_whitespace().collect::<Vec<_>>().join(" ")
        );
        assert_eq!(
            paper.summary,
            paper
                .summary
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        );
        if let Some(pdf_url) = &paper.pdf_url {
            assert!(!pdf_url.contains('"'));
        }
    }

    let _ = extract_tag(xml, "entry");
    let _ = extract_tag(xml, "title");
    let _ = extract_link_href(xml, Some("related"));
    let _ = extract_link_href(xml, None);
    let _ = extract_authors(xml);
    let _ = extract_primary_category(xml);
    let _ = extract_categories(xml);
    let _ = extract_total_results(xml);
}

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = Unstructured::new(data).arbitrary::<ArxivAtomFuzz<'_>>() {
        match input.mode % 2 {
            0 => {
                if let Ok(xml) = std::str::from_utf8(bounded(input.raw_xml, MAX_RAW_XML_BYTES)) {
                    exercise_xml(xml);
                }
            }
            _ => {
                let (xml, expected_entries) = structured_feed(&input);
                let papers = parse_atom_entries(&xml);
                assert_eq!(papers.len(), expected_entries);
                exercise_xml(&xml);
            }
        }
    } else if let Ok(xml) = std::str::from_utf8(bounded(data, MAX_RAW_XML_BYTES)) {
        exercise_xml(xml);
    }
});
