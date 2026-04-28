#![no_main]

//! Fuzz target for `TailscaleTag::is_fcp_tag` ↔ `fcp_suffix` agreement
//! and `fcp_tag` constructor round-trip (tag.rs:60-92).
//!
//! `TailscaleTag` has three FCP-prefix functions:
//!   - `fcp_tag(suffix)` constructor (always emits `tag:fcp-{suffix}`)
//!   - `is_fcp_tag()` predicate (`starts_with("tag:fcp-")`)
//!   - `fcp_suffix()` extractor (`strip_prefix("tag:fcp-")`)
//!
//! Existing `tailscale_acl` exercises them for panic-freedom but not
//! as agreement MRs. A regression that desynchronized the predicate
//! from the extractor (e.g., is_fcp_tag returning true while
//! fcp_suffix returning None) would let an FCP-classified tag appear
//! to have no suffix, corrupting downstream zone routing.
//!
//! Properties asserted:
//!
//!   1. **fcp_tag round-trip**: `fcp_tag(s).fcp_suffix() == Some(s)`
//!      and `is_fcp_tag()` returns true.
//!   2. **Predicate ↔ extractor agreement**: for any TailscaleTag,
//!      `is_fcp_tag()` returns true iff `fcp_suffix()` returns
//!      `Some(_)`.
//!   3. **Non-FCP tag**: a tag without the `tag:fcp-` prefix returns
//!      `is_fcp_tag()=false` AND `fcp_suffix()=None`.
//!   4. **as_str round-trip**: `TailscaleTag::new(t).as_str() == t`
//!      for valid t.
//!
//!   Once-gated anchors verify the canonical example pairs from
//!   the documentation comments.

use arbitrary::{Arbitrary, Unstructured};
use fcp_tailscale::TailscaleTag;
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

const MAX_LEN: usize = 256;

static TAG_PREDICATES_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    suffix: String,
    arbitrary_tag: String,
}

fuzz_target!(|data: &[u8]| {
    TAG_PREDICATES_ANCHOR.call_once(assert_tag_predicates_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };
    if input.suffix.len() > MAX_LEN || input.arbitrary_tag.len() > MAX_LEN {
        return;
    }

    // ── PROPERTY 1: fcp_tag round-trip ────────────────────────────────
    let constructed = TailscaleTag::fcp_tag(&input.suffix);
    assert!(
        constructed.is_fcp_tag(),
        "fcp_tag({:?}) does not return is_fcp_tag()=true",
        input.suffix
    );
    assert_eq!(
        constructed.fcp_suffix(),
        Some(input.suffix.as_str()),
        "fcp_tag({:?}).fcp_suffix() did not round-trip",
        input.suffix
    );

    // ── PROPERTY 2: predicate ↔ extractor agreement on any tag ───────
    if let Ok(tag) = TailscaleTag::new(input.arbitrary_tag.clone()) {
        let is_fcp = tag.is_fcp_tag();
        let suffix = tag.fcp_suffix();
        assert_eq!(
            is_fcp,
            suffix.is_some(),
            "is_fcp_tag() ({is_fcp}) disagrees with fcp_suffix().is_some() ({}) \
             for tag {:?}",
            suffix.is_some(),
            input.arbitrary_tag
        );

        // ── PROPERTY 4: as_str round-trip ────────────────────────────
        assert_eq!(
            tag.as_str(),
            input.arbitrary_tag,
            "as_str round-trip lost or altered bytes"
        );
    }
});

/// Once-gated anchors verifying the canonical doc-comment examples.
fn assert_tag_predicates_anchored() {
    // Doc example: fcp_tag("work") → "tag:fcp-work".
    let work = TailscaleTag::fcp_tag("work");
    assert_eq!(
        work.as_str(),
        "tag:fcp-work",
        "ANCHOR: fcp_tag(\"work\") did not produce \"tag:fcp-work\""
    );
    assert!(
        work.is_fcp_tag(),
        "ANCHOR: fcp_tag(\"work\").is_fcp_tag() false"
    );
    assert_eq!(
        work.fcp_suffix(),
        Some("work"),
        "ANCHOR: fcp_tag(\"work\").fcp_suffix() != Some(\"work\")"
    );

    // Doc example: TailscaleTag::new("tag:fcp-work") = is_fcp + suffix=Some.
    let parsed = TailscaleTag::new("tag:fcp-work").expect("anchor parse");
    assert!(
        parsed.is_fcp_tag(),
        "ANCHOR: parsed FCP tag is_fcp_tag=false"
    );
    assert_eq!(parsed.fcp_suffix(), Some("work"));

    // Doc example: TailscaleTag::new("tag:server") → not FCP.
    let server = TailscaleTag::new("tag:server").expect("anchor parse non-FCP");
    assert!(
        !server.is_fcp_tag(),
        "ANCHOR REGRESSION: \"tag:server\" classified as FCP tag"
    );
    assert_eq!(
        server.fcp_suffix(),
        None,
        "ANCHOR REGRESSION: \"tag:server\".fcp_suffix() returned Some — \
         is_fcp_tag/fcp_suffix predicates desynchronized"
    );

    // Edge case: fcp_tag with empty suffix is still a valid FCP tag.
    let empty = TailscaleTag::fcp_tag("");
    assert_eq!(
        empty.as_str(),
        "tag:fcp-",
        "ANCHOR: fcp_tag(\"\") didn't produce \"tag:fcp-\""
    );
    assert!(
        empty.is_fcp_tag(),
        "ANCHOR: fcp_tag(\"\") not classified as FCP"
    );
    assert_eq!(
        empty.fcp_suffix(),
        Some(""),
        "ANCHOR: fcp_tag(\"\").fcp_suffix() != Some(\"\")"
    );
}
