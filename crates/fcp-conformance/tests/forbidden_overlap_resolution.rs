//! Regression guard for the Phase I.2 forbidden-overlap cleanup ledger.
//!
//! `test_zero_pending_overlap_pairs` is intentionally ignored until the three
//! child beads resolve the holdouts. `test_baseline_unchanged` runs now and
//! prevents silently broadening the pending set.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use fcp_crypto::{HybridSignable, SignedEnvelope};
use fcp_protocol::{HybridSignedFcpsFrame, SignedFcpsFramePayload};

const STATUS_DOC: &str = "docs/cleanup/forbidden_overlap_status.md";
const FCP_CRYPTO_HYBRID_RS: &str = include_str!("../../fcp-crypto/src/hybrid.rs");
const FCP_PROTOCOL_FCPS_RS: &str = include_str!("../../fcp-protocol/src/fcps.rs");

const EXPECTED_BASELINE: &[ExpectedOverlap] = &[
    ExpectedOverlap {
        id: "I2-HOST-MESH",
        from: "fcp-host",
        to: "fcp-mesh",
    },
    ExpectedOverlap {
        id: "I2-STORE-RAPTORQ",
        from: "fcp-store",
        to: "fcp-raptorq",
    },
    ExpectedOverlap {
        id: "I2-PROTOCOL-CRYPTO",
        from: "fcp-protocol",
        to: "fcp-crypto",
    },
];

#[derive(Debug)]
struct ExpectedOverlap {
    id: &'static str,
    from: &'static str,
    to: &'static str,
}

#[derive(Debug)]
struct OverlapRow {
    id: String,
    from: String,
    to: String,
    status: String,
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates directory")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn status_doc() -> String {
    fs::read_to_string(workspace_root().join(STATUS_DOC))
        .expect("read forbidden-overlap status doc")
}

fn field<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let prefix = format!("{name}=");
    line.split_whitespace()
        .find_map(|part| part.strip_prefix(&prefix))
        .map(|value| value.trim_end_matches("-->").trim())
}

fn summary_value(doc: &str, name: &str) -> usize {
    let summary_line = doc
        .lines()
        .find(|line| line.contains("forbidden-overlap-summary:"))
        .expect("machine-readable forbidden-overlap summary");
    field(summary_line, name)
        .unwrap_or_else(|| panic!("summary field `{name}` is present"))
        .parse()
        .unwrap_or_else(|err| panic!("summary field `{name}` parses as usize: {err}"))
}

fn overlap_rows(doc: &str) -> Vec<OverlapRow> {
    doc.lines()
        .filter(|line| line.contains("forbidden-overlap-row:"))
        .map(|line| OverlapRow {
            id: field(line, "id").expect("row id").to_owned(),
            from: field(line, "from").expect("row from crate").to_owned(),
            to: field(line, "to").expect("row target crate").to_owned(),
            status: field(line, "status").expect("row status").to_owned(),
        })
        .collect()
}

fn row_status<'a>(rows: &'a [OverlapRow], id: &str) -> &'a str {
    rows.iter()
        .find(|row| row.id == id)
        .unwrap_or_else(|| panic!("overlap row `{id}` is present"))
        .status
        .as_str()
}

fn assert_crypto_envelope_alias<T: HybridSignable>(_alias: Option<SignedEnvelope<T>>) {}

#[test]
#[ignore = "Phase I.2 child beads still track three pending holdouts"]
fn test_zero_pending_overlap_pairs() {
    let doc = status_doc();
    assert_eq!(
        summary_value(&doc, "pending"),
        0,
        "forbidden-overlap cleanup is incomplete; run the Phase I.2 child beads \
         and update {STATUS_DOC} only after the holdouts are resolved"
    );
}

#[test]
fn test_baseline_unchanged() {
    let doc = status_doc();
    let rows = overlap_rows(&doc);

    let expected: BTreeSet<_> = EXPECTED_BASELINE
        .iter()
        .map(|row| (row.id.to_owned(), row.from.to_owned(), row.to.to_owned()))
        .collect();
    let actual: BTreeSet<_> = rows
        .iter()
        .map(|row| (row.id.clone(), row.from.clone(), row.to.clone()))
        .collect();

    assert_eq!(
        actual, expected,
        "forbidden-overlap baseline changed unexpectedly; file a new detail bead \
         before adding or replacing rows in {STATUS_DOC}"
    );
    assert_eq!(
        summary_value(&doc, "baseline_pairs"),
        EXPECTED_BASELINE.len(),
        "baseline pair count must match EXPECTED_BASELINE"
    );
    assert_eq!(
        summary_value(&doc, "current_pairs"),
        rows.len(),
        "summary current_pairs must match machine-readable rows"
    );

    let pending_rows = rows.iter().filter(|row| row.status == "pending").count();
    let resolved_rows = rows.iter().filter(|row| row.status == "resolved").count();
    assert_eq!(
        summary_value(&doc, "pending"),
        pending_rows,
        "summary pending count must match rows"
    );
    assert_eq!(
        summary_value(&doc, "resolved"),
        resolved_rows,
        "summary resolved count must match rows"
    );
    assert_eq!(
        pending_rows + resolved_rows,
        rows.len(),
        "rows must be either pending or resolved"
    );
}

#[test]
fn test_protocol_crypto_overlap_uses_crypto_envelope_owner() {
    assert_crypto_envelope_alias::<SignedFcpsFramePayload>(None::<HybridSignedFcpsFrame>);

    assert!(
        FCP_CRYPTO_HYBRID_RS.contains("pub struct SignedEnvelope<T>"),
        "fcp-crypto must remain the canonical SignedEnvelope owner"
    );
    assert!(
        FCP_PROTOCOL_FCPS_RS
            .contains("pub type HybridSignedFcpsFrame = SignedEnvelope<SignedFcpsFramePayload>;"),
        "fcp-protocol hybrid FCPS signing must use fcp_crypto::SignedEnvelope"
    );
    assert!(
        FCP_PROTOCOL_FCPS_RS.contains("impl HybridSignable for SignedFcpsFramePayload"),
        "fcp-protocol payloads that need hybrid signing must implement the crypto adapter"
    );
    assert!(
        !FCP_PROTOCOL_FCPS_RS.contains("pub struct SignedEnvelope")
            && !FCP_PROTOCOL_FCPS_RS.contains("struct SignedEnvelope<"),
        "fcp-protocol must not define a protocol-local SignedEnvelope owner"
    );

    let doc = status_doc();
    let rows = overlap_rows(&doc);
    assert_eq!(
        row_status(&rows, "I2-PROTOCOL-CRYPTO"),
        "resolved",
        "the status doc may only mark the protocol/crypto overlap resolved when \
         the canonical fcp_crypto::SignedEnvelope alias remains in fcp-protocol"
    );
}
