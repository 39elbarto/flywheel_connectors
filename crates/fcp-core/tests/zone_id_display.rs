use fcp_core::{ZoneId, ZoneIdError};

fn canonical_zone_cases() -> Result<[(&'static str, ZoneId); 6], ZoneIdError> {
    Ok([
        ("z:owner", ZoneId::owner()),
        ("z:private", ZoneId::private()),
        ("z:work", ZoneId::work()),
        ("z:project:demo", "z:project:demo".parse()?),
        ("z:community", ZoneId::community()),
        ("z:public", ZoneId::public()),
    ])
}

#[test]
fn zone_id_display_formats_canonical_variants() -> Result<(), ZoneIdError> {
    for (expected, zone) in canonical_zone_cases()? {
        assert_eq!(format!("{zone}"), expected);
    }

    Ok(())
}

#[test]
fn zone_id_from_str_roundtrips_through_display_for_canonical_variants() -> Result<(), ZoneIdError> {
    for (expected, _) in canonical_zone_cases()? {
        let parsed: ZoneId = expected.parse()?;
        let formatted = parsed.to_string();
        let reparsed: ZoneId = formatted.parse()?;

        assert_eq!(formatted, expected);
        assert_eq!(reparsed, parsed);
    }

    Ok(())
}
