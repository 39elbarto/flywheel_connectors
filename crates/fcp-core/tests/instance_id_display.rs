use std::str::FromStr;

use fcp_core::InstanceId;

const CANONICAL_INSTANCE_IDS: &[&str] = &["inst_1", "inst-2", "inst.3.alpha"];

#[test]
fn instance_id_display_matches_canonical_string() {
    for canonical in CANONICAL_INSTANCE_IDS {
        let id = InstanceId::from_str(canonical).expect("canonical InstanceId parses");

        assert_eq!(id.as_str(), *canonical);
        assert_eq!(id.to_string(), *canonical);
        assert_eq!(format!("{id}"), *canonical);
    }
}

#[test]
fn instance_id_from_str_roundtrips_through_display() {
    for canonical in CANONICAL_INSTANCE_IDS {
        let parsed = canonical
            .parse::<InstanceId>()
            .expect("canonical InstanceId parses");
        let reparsed = parsed
            .to_string()
            .parse::<InstanceId>()
            .expect("displayed InstanceId parses");

        assert_eq!(parsed, reparsed);
    }
}

#[test]
fn instance_id_equality_is_string_value_based() {
    let first_from_parse = "inst.same"
        .parse::<InstanceId>()
        .expect("canonical InstanceId parses");
    let second_from_try_from =
        InstanceId::try_from("inst.same".to_owned()).expect("canonical InstanceId parses");
    let different = "inst.different"
        .parse::<InstanceId>()
        .expect("canonical InstanceId parses");

    assert_eq!(first_from_parse, second_from_try_from);
    assert_ne!(first_from_parse, different);
}
