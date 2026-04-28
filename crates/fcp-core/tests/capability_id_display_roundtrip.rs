use fcp_core::CapabilityId;

type TestResult = Result<(), fcp_core::IdValidationError>;

#[test]
fn capability_id_display_and_from_str_roundtrip_preserves_canonical_text() -> TestResult {
    let cases = [
        "cap.read",
        "cap.discord.send_message",
        "fcp.example:files.read-v2",
        "9cap",
        "a.b_c:d-e",
    ];

    for canonical in cases {
        let parsed = canonical.parse::<CapabilityId>()?;

        assert_eq!(parsed.to_string(), canonical);
        assert_eq!(format!("{parsed}"), canonical);
        assert_eq!(parsed.as_str(), canonical);
        assert_eq!(parsed.as_ref(), canonical);

        let reparsed = parsed.to_string().parse::<CapabilityId>()?;
        assert_eq!(reparsed, parsed);
    }

    Ok(())
}

#[test]
fn capability_id_construction_paths_are_equal_for_same_canonical_text() -> TestResult {
    let canonical = "cap.connector.invoke-v2";

    let via_new = CapabilityId::new(canonical)?;
    let via_try_from = CapabilityId::try_from(canonical.to_owned())?;
    let via_parse = canonical.parse::<CapabilityId>()?;
    let via_static = CapabilityId::from_static(canonical);
    let via_clone = via_new.clone();
    let via_display_roundtrip = via_new.to_string().parse::<CapabilityId>()?;

    for constructed in [
        via_try_from,
        via_parse,
        via_static,
        via_clone,
        via_display_roundtrip,
    ] {
        assert_eq!(constructed, via_new);
        assert_eq!(constructed.to_string(), canonical);
    }

    let owned: String = via_new.into();
    assert_eq!(owned, canonical);

    Ok(())
}
