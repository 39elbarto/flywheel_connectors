#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use fcp_tailscale::{TailscaleTag, ZoneAclGenerator, ZoneAclRule, ZoneTagMapping};
use libfuzzer_sys::fuzz_target;
use serde::Deserialize;

const MAX_ZONE_LEN: usize = 128;
const MAX_TAG_LEN: usize = 128;

#[derive(Arbitrary, Debug, Deserialize)]
struct TailscaleAclInput {
    zone_id: String,
    tag: String,
    symbol_port: u16,
    control_port: u16,
}

fn clamp_zone(raw: &str, max_len: usize) -> String {
    raw.chars().take(max_len).collect()
}

fuzz_target!(|data: &[u8]| {
    let input = if let Ok(seed) = serde_json::from_slice::<TailscaleAclInput>(data) {
        seed
    } else {
        let mut unstructured = Unstructured::new(data);
        let Ok(seed) = TailscaleAclInput::arbitrary(&mut unstructured) else {
            return;
        };
        seed
    };

    let zone_id = clamp_zone(&input.zone_id, MAX_ZONE_LEN);
    let tag_value = clamp_zone(&input.tag, MAX_TAG_LEN);

    let _ = ZoneTagMapping::validate_zone_id(&zone_id);

    if let Ok(tag) = TailscaleTag::new(tag_value) {
        let _ = tag.is_fcp_tag();
        let _ = tag.fcp_suffix();
        if let Some(zone) = ZoneTagMapping::tag_to_zone(&tag) {
            assert!(ZoneTagMapping::is_valid_zone_id(&zone));
        }
    }

    if let Ok(tag) = ZoneTagMapping::zone_to_tag(&zone_id) {
        let round_trip = ZoneTagMapping::tag_to_zone(&tag);
        assert_eq!(round_trip.as_deref(), Some(zone_id.as_str()));
    }

    let generator = ZoneAclGenerator::new(input.symbol_port, input.control_port);
    if let Ok(rule) = generator.zone_access_rule(&zone_id) {
        assert_eq!(rule.action, "accept");
        let encoded = serde_json::to_vec(&rule).unwrap_or_default();
        let decoded = serde_json::from_slice::<ZoneAclRule>(&encoded).unwrap_or(rule.clone());
        assert_eq!(decoded.src, rule.src);
        assert_eq!(decoded.dst, rule.dst);
    }

    let _ = generator.all_zone_rules();
});
