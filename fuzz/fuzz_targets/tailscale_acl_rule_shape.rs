#![no_main]

//! Fuzz target for `fcp_tailscale::ZoneAclGenerator` rule-generation
//! invariants and `ZoneAclRule` serde round-trip (tag.rs:266-333).
//!
//! `ZoneAclGenerator` produces the ACL rules fed into Tailscale's ACL
//! system. The rule shape encodes a security invariant: `src` tag
//! equals every `dst` entry's tag prefix; `action="accept"`; and `dst`
//! contains exactly the (symbol_port, control_port) pair. A regression
//! that dropped one of the dst entries would silently widen or narrow
//! the ACL surface — most dangerously, dropping the control_port
//! restriction would expose mesh control-plane traffic to any zone
//! member, defeating the defense-in-depth gate documented at
//! tag.rs:262-264.
//!
//! Existing fcp-tailscale fuzz coverage:
//!   - `tailscale_acl`               — ZoneTagMapping zone↔tag round-trip
//!   - `tailscale_status_parse`      — TailscaleStatus JSON
//!   - `tailscale_attestation_binding` — NodeKeyAttestation sign/verify
//!
//! NOT covered: ZoneAclGenerator's rule-generation invariants OR
//! ZoneAclRule's serde surface.
//!
//! Properties asserted:
//!
//!   1. **Action invariant**: every emitted rule has `action == "accept"`.
//!   2. **Source/destination consistency**: `rule.src` has exactly one
//!      tag and that tag is the prefix of every `rule.dst` entry.
//!   3. **Port cardinality + content**: `rule.dst` contains exactly two
//!      entries, `<tag>:<symbol_port>` and `<tag>:<control_port>`.
//!   4. **Round-trip with tag_to_zone**: zone_access_rule(zone_id) →
//!      extract tag from `src[0]` → `tag_to_zone(tag) == Some(zone_id)`
//!      when input was a canonical zone.
//!   5. **JSON round-trip**: `serde_json::to_string → from_str` preserves
//!      ZoneAclRule on its canonical projection (action, sorted-src,
//!      sorted-dst).
//!   6. **all_zone_rules cardinality + uniqueness**: produces exactly
//!      `standard_zones().len()` rules, each with a distinct src tag.
//!
//!   Once-gated regression anchors:
//!     (a) Default generator's all_zone_rules() yields 5 rules with
//!         ports 4200/4201, action="accept", and src tags forming the
//!         canonical FCP zone set.
//!     (b) zone_access_rule with explicit ports (8080, 8081) wires
//!         those ports through to the dst entries.

use arbitrary::{Arbitrary, Unstructured};
use fcp_tailscale::{TailscaleTag, ZoneAclGenerator, ZoneAclRule, ZoneTagMapping};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

const STANDARD_ZONES: &[&str] = &["z:owner", "z:private", "z:work", "z:community", "z:public"];

static RULE_SHAPE_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    symbol_port: u16,
    control_port: u16,
    /// Selector among the standard zones (we restrict to canonical
    /// zones because this target probes rule-shape invariants — the
    /// arbitrary-zone parser is covered by tailscale_acl).
    zone_selector: u8,
}

fn pick_zone(selector: u8) -> &'static str {
    STANDARD_ZONES[(selector as usize) % STANDARD_ZONES.len()]
}

/// Assert the per-rule shape invariants documented in the doc-comment
/// (Properties 1, 2, 3). Returns the extracted tag string for further
/// round-trip checks.
fn assert_rule_shape(rule: &ZoneAclRule, symbol_port: u16, control_port: u16) -> String {
    // Property 1: action invariant.
    assert_eq!(
        rule.action, "accept",
        "ZoneAclRule action MUST be \"accept\"; got {:?}",
        rule.action
    );

    // Property 2: src cardinality.
    assert_eq!(
        rule.src.len(),
        1,
        "ZoneAclRule.src MUST contain exactly one tag; got {} entries",
        rule.src.len()
    );
    let src_tag = rule.src[0].clone();

    // Property 3: dst cardinality + content.
    assert_eq!(
        rule.dst.len(),
        2,
        "ZoneAclRule.dst MUST contain exactly 2 entries (symbol+control \
         ports); got {} entries — port-drop regression would widen or \
         narrow the ACL surface",
        rule.dst.len()
    );

    let expected_symbol = format!("{src_tag}:{symbol_port}");
    let expected_control = format!("{src_tag}:{control_port}");
    assert!(
        rule.dst.contains(&expected_symbol),
        "ZoneAclRule.dst missing symbol-port entry {expected_symbol:?}; got {:?}",
        rule.dst
    );
    assert!(
        rule.dst.contains(&expected_control),
        "ZoneAclRule.dst missing control-port entry {expected_control:?}; got {:?}",
        rule.dst
    );

    // Sanity: every dst MUST start with the src tag prefix (closes
    // src/dst tag-mismatch surface).
    let prefix = format!("{src_tag}:");
    for d in &rule.dst {
        assert!(
            d.starts_with(&prefix),
            "ZoneAclRule.dst entry {d:?} does not start with src tag {prefix:?} \
             — src/dst mismatch surface; inbound traffic from unintended zones \
             could reach the listening port"
        );
    }

    src_tag
}

fuzz_target!(|data: &[u8]| {
    RULE_SHAPE_ANCHOR.call_once(assert_rule_shape_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    // Skip the symbol_port == control_port degenerate input. The dst
    // would collapse to a single distinct entry but the rule still has
    // 2 strings — this is a documentation-grey-area of the API and not
    // the surface we probe.
    if input.symbol_port == input.control_port {
        return;
    }

    let acl_gen = ZoneAclGenerator::new(input.symbol_port, input.control_port);
    let zone_id = pick_zone(input.zone_selector);

    // ── PROPERTIES 1+2+3: per-rule shape ───────────────────────────────
    let rule = acl_gen
        .zone_access_rule(zone_id)
        .expect("zone_access_rule MUST succeed for a standard zone");
    let src_tag_str = assert_rule_shape(&rule, input.symbol_port, input.control_port);

    // ── PROPERTY 4: round-trip with tag_to_zone ────────────────────────
    let tag = TailscaleTag::new(&src_tag_str)
        .expect("ZoneAclRule.src tag MUST construct via TailscaleTag::new");
    let recovered = ZoneTagMapping::tag_to_zone(&tag).expect(
        "tag_to_zone MUST recover the zone from ZoneAclRule.src tag — \
         zone↔tag bijection broken at the rule-generation boundary",
    );
    assert_eq!(
        recovered, zone_id,
        "tag_to_zone({src_tag_str:?}) returned {recovered:?}; expected {zone_id:?}"
    );

    // ── PROPERTY 5: JSON round-trip ────────────────────────────────────
    let json = serde_json::to_string(&rule).expect("ZoneAclRule MUST serialize to JSON");
    let decoded: ZoneAclRule =
        serde_json::from_str(&json).expect("ZoneAclRule JSON MUST round-trip");
    assert_eq!(
        decoded.action, rule.action,
        "JSON round-trip changed ZoneAclRule.action"
    );
    assert_eq!(
        decoded.src, rule.src,
        "JSON round-trip changed ZoneAclRule.src"
    );
    assert_eq!(
        decoded.dst, rule.dst,
        "JSON round-trip changed ZoneAclRule.dst"
    );

    // ── PROPERTY 6: all_zone_rules cardinality + uniqueness ────────────
    let all_rules = acl_gen
        .all_zone_rules()
        .expect("all_zone_rules MUST succeed for the default standard-zones set");
    assert_eq!(
        all_rules.len(),
        STANDARD_ZONES.len(),
        "all_zone_rules cardinality MUST equal standard_zones().len(); \
         got {} rules vs {} zones",
        all_rules.len(),
        STANDARD_ZONES.len()
    );

    let mut seen = std::collections::HashSet::new();
    for r in &all_rules {
        let src = assert_rule_shape(r, input.symbol_port, input.control_port);
        assert!(
            seen.insert(src.clone()),
            "all_zone_rules emitted duplicate src tag {src:?} — \
             non-injective standard-zone → tag mapping in rule generation"
        );
    }
});

/// Once-gated regression anchors: default generator + explicit-port
/// generator both yield the documented rule shape.
fn assert_rule_shape_anchored() {
    // (a) Default generator: 5 rules, ports 4200/4201.
    let default_gen = ZoneAclGenerator::default();
    let rules = default_gen
        .all_zone_rules()
        .expect("anchor default all_zone_rules");
    assert_eq!(
        rules.len(),
        5,
        "ANCHOR REGRESSION: default generator's all_zone_rules() emitted {} \
         rules; expected 5 (z:owner, z:private, z:work, z:community, z:public)",
        rules.len()
    );

    let mut seen_zones = std::collections::HashSet::new();
    for r in &rules {
        let src = assert_rule_shape(r, 4200, 4201);
        // Recover zone from tag and accumulate.
        let tag = TailscaleTag::new(&src).expect("anchor TailscaleTag::new");
        let zone = ZoneTagMapping::tag_to_zone(&tag).expect("anchor tag_to_zone");
        seen_zones.insert(zone);
    }
    let expected: std::collections::HashSet<String> =
        STANDARD_ZONES.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        seen_zones, expected,
        "ANCHOR REGRESSION: default generator's all_zone_rules() did not cover \
         the canonical FCP zone set; got {seen_zones:?} vs expected {expected:?}"
    );

    // (b) Explicit-port generator: ports 8080/8081 wire through to dst.
    let custom = ZoneAclGenerator::new(8080, 8081);
    let rule = custom
        .zone_access_rule("z:work")
        .expect("anchor zone_access_rule(z:work)");
    let src = assert_rule_shape(&rule, 8080, 8081);
    let expected_8080 = format!("{src}:8080");
    let expected_8081 = format!("{src}:8081");
    assert!(
        rule.dst.contains(&expected_8080) && rule.dst.contains(&expected_8081),
        "ANCHOR REGRESSION: custom-port (8080/8081) zone_access_rule(z:work) did \
         not emit both ports in dst; got {:?}",
        rule.dst
    );
}
