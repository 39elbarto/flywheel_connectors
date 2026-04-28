use fcp_core::CredentialId;
use uuid::Uuid;

const CANONICAL_CREDENTIAL_ID: &str = "11223344-5566-7788-99aa-bbccddeeff00";
const DIFFERENT_CREDENTIAL_ID: &str = "11223344-5566-7788-99aa-bbccddeeff01";

#[test]
fn credential_id_display_parse_roundtrips() -> Result<(), uuid::Error> {
    let parsed = CredentialId::parse(CANONICAL_CREDENTIAL_ID)?;

    assert_eq!(parsed.to_string(), CANONICAL_CREDENTIAL_ID);

    let displayed = parsed.to_string();
    let reparsed = CredentialId::parse(&displayed)?;
    let constructed = CredentialId::from_uuid(Uuid::parse_str(CANONICAL_CREDENTIAL_ID)?);

    assert_eq!(parsed, reparsed);
    assert_eq!(parsed, constructed);
    assert_eq!(format!("{parsed}"), CANONICAL_CREDENTIAL_ID);

    Ok(())
}

#[test]
fn credential_id_parse_canonicalizes_uuid_case() -> Result<(), uuid::Error> {
    let upper = CredentialId::parse("11223344-5566-7788-99AA-BBCCDDEEFF00")?;
    let mixed = CredentialId::parse("11223344-5566-7788-99Aa-BbCcDdEeFf00")?;
    let lower = CredentialId::parse(CANONICAL_CREDENTIAL_ID)?;

    assert_eq!(upper, lower);
    assert_eq!(mixed, lower);
    assert_eq!(upper.to_string(), CANONICAL_CREDENTIAL_ID);
    assert_eq!(mixed.to_string(), CANONICAL_CREDENTIAL_ID);

    Ok(())
}

#[test]
fn credential_id_equality_matches_uuid_identity() -> Result<(), uuid::Error> {
    let via_parse = CredentialId::parse(CANONICAL_CREDENTIAL_ID)?;
    let via_parse_method = CredentialId::parse(CANONICAL_CREDENTIAL_ID)?;
    let via_uuid = CredentialId::from_uuid(Uuid::parse_str(CANONICAL_CREDENTIAL_ID)?);
    let different = CredentialId::parse(DIFFERENT_CREDENTIAL_ID)?;

    assert_eq!(via_parse, via_parse_method);
    assert_eq!(via_parse, via_uuid);
    assert_ne!(via_parse, different);

    Ok(())
}

#[test]
fn credential_id_parse_rejects_invalid_forms() {
    for invalid in [
        "",
        "not-a-uuid",
        "11223344-5566-7788-99aa-bbccddeeff0",
        "11223344-5566-7788-99aa-bbccddeeff000",
        " 11223344-5566-7788-99aa-bbccddeeff00",
        "11223344-5566-7788-99aa-bbccddeeff00 ",
    ] {
        assert!(CredentialId::parse(invalid).is_err(), "{invalid}");
    }
}
