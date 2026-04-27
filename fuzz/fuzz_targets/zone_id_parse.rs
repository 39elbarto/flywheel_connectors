#![no_main]

//! Fuzz target for `fcp_core::ZoneId` string parsers.
//!
//! ZoneId is the zone-access security primitive: every capability,
//! object, and event in FCP is scoped to exactly one ZoneId. Mis-parsing
//! a hostile input — accepting an "almost-valid" string that diverges
//! by one byte from a real zone, or panicking on adversarial UTF-8 —
//! has direct authorization-bypass implications.
//!
//! `ZoneId::validate` has eight rejection branches (empty, length cap
//! at 64 bytes, ASCII, `z:` prefix, empty segment, `z:proj-` reserved
//! prefix, project-zone leading/trailing dash, char allowlist
//! [a-z0-9:_-]). `from_tailscale_tag` adds a tag→zone mapping that
//! interacts with the same validator.
//!
//! Properties asserted:
//!
//!   1. `<ZoneId as FromStr>::from_str` is panic-free over arbitrary
//!      UTF-8 input.
//!   2. Accepted parses preserve canonical form: `parsed.as_str()`
//!      equals the input string byte-for-byte.
//!   3. Round-trip through `to_tailscale_tag` → `from_tailscale_tag`
//!      yields the original `ZoneId` for any zone the parser accepted.
//!   4. `from_tailscale_tag` is panic-free over arbitrary input AND
//!      every accepted output passes `from_str` validation (i.e., the
//!      tag-derived zone is a valid zone).
//!   5. Standard zones (owner/private/work/community/public) are
//!      always accepted by `from_str` and round-trip unchanged.

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::ZoneId;
use libfuzzer_sys::fuzz_target;
use std::str::FromStr;

const MAX_INPUT_LEN: usize = 256;

#[derive(Arbitrary, Debug)]
struct Input {
    /// Bytes interpreted as UTF-8 for the zone-string parse path.
    zone_bytes: Vec<u8>,
    /// Bytes interpreted as UTF-8 for the tailscale-tag parse path.
    tag_bytes: Vec<u8>,
}

fn truncate_str(s: &str) -> &str {
    // Find a UTF-8 boundary <= MAX_INPUT_LEN to avoid splitting in
    // the middle of a multi-byte sequence.
    if s.len() <= MAX_INPUT_LEN {
        return s;
    }
    let mut end = MAX_INPUT_LEN;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    let zone_str_owned = String::from_utf8_lossy(&input.zone_bytes).into_owned();
    let zone_str = truncate_str(&zone_str_owned);

    let tag_str_owned = String::from_utf8_lossy(&input.tag_bytes).into_owned();
    let tag_str = truncate_str(&tag_str_owned);

    // ── PROPERTY 1: from_str is panic-free ──────────────────────────────
    let from_str_result = ZoneId::from_str(zone_str);

    // ── PROPERTY 2: canonical form preserved ────────────────────────────
    if let Ok(zone) = &from_str_result {
        assert_eq!(
            zone.as_str(),
            zone_str,
            "ZoneId::from_str must not transform the input — the parsed canonical \
             form differs from the accepted source string"
        );

        // ── PROPERTY 3: tailscale-tag round-trip ────────────────────────
        // Every accepted zone must round-trip through the tag mapping.
        // Caveat: `to_tailscale_tag` rewrites underscores → dashes
        // (capability.rs:515,517) for the FCP/Tailscale tag-charset
        // intersection. That mapping is intentionally lossy for zones
        // containing `_`, so skip the round-trip for those cases —
        // accepting them would be a separate API contract assertion.
        if !zone_str.contains('_') {
            let tag = zone.to_tailscale_tag();
            match ZoneId::from_tailscale_tag(&tag) {
                Ok(round_trip) => assert_eq!(
                    round_trip.as_str(),
                    zone.as_str(),
                    "tag round-trip diverged: zone={zone_str} tag={tag} \
                     round_trip={round}",
                    round = round_trip.as_str()
                ),
                Err(err) => panic!(
                    "to_tailscale_tag→from_tailscale_tag failed on accepted zone \
                     {zone_str}: {err}"
                ),
            }
        }
    }

    // ── PROPERTY 4: from_tailscale_tag is panic-free + accepted outputs
    //               pass from_str ──────────────────────────────────────
    if let Ok(tag_zone) = ZoneId::from_tailscale_tag(tag_str) {
        let s = tag_zone.as_str().to_owned();
        // Re-parse the derived zone string through the primary parser.
        // If the tag mapper accepted but the canonical parser rejects,
        // the two paths disagree on what counts as a valid ZoneId.
        match ZoneId::from_str(&s) {
            Ok(reparsed) => assert_eq!(
                reparsed.as_str(),
                s,
                "tag-derived zone {s} re-parsed to a different canonical form"
            ),
            Err(err) => panic!(
                "from_tailscale_tag accepted tag {tag_str} producing zone {s}, \
                 but ZoneId::from_str rejects that zone: {err}"
            ),
        }
    }

    // ── PROPERTY 5: standard zones are always valid ─────────────────────
    // This anchors the parser to the documented zone hierarchy. A
    // regression that broke the standard-zone constructors (or the
    // validator's char-allowlist for them) would surface immediately.
    for canonical in [
        ZoneId::OWNER,
        ZoneId::PRIVATE,
        ZoneId::WORK,
        ZoneId::COMMUNITY,
        ZoneId::PUBLIC,
    ] {
        let parsed = ZoneId::from_str(canonical)
            .unwrap_or_else(|err| panic!("standard zone {canonical} rejected: {err}"));
        assert_eq!(parsed.as_str(), canonical);
    }
});
