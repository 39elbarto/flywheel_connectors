use std::str::FromStr;

use fcp_core::{IdValidationError, PrincipalId};

#[test]
fn principal_ids_with_same_kind_and_literal_compare_equal() -> Result<(), IdValidationError> {
    for literal in ["user:alice", "agent:cod6", "service:registry"] {
        let via_new = PrincipalId::new(literal)?;
        let via_from_str = PrincipalId::from_str(literal)?;
        let via_try_from = PrincipalId::try_from(literal.to_owned())?;

        assert_eq!(via_new, via_from_str);
        assert_eq!(via_from_str, via_try_from);
        assert_eq!(via_new.as_str(), literal);
    }

    Ok(())
}

#[test]
fn principal_ids_with_different_kinds_do_not_compare_equal() -> Result<(), IdValidationError> {
    let user = PrincipalId::new("user:alice")?;
    let agent = PrincipalId::new("agent:alice")?;
    let service = PrincipalId::new("service:alice")?;

    assert_ne!(user, agent);
    assert_ne!(user, service);
    assert_ne!(agent, service);

    Ok(())
}

#[test]
fn principal_id_roundtrip_is_stable_across_kinds() -> Result<(), IdValidationError> {
    for literal in [
        "user:alice",
        "user:team-admin",
        "agent:cod6",
        "agent:fcp_worker",
        "service:registry",
        "service:policy.engine",
    ] {
        let parsed = PrincipalId::from_str(literal)?;
        let displayed = parsed.to_string();

        assert_eq!(displayed, literal);
        assert_eq!(PrincipalId::from_str(&displayed)?, parsed);
        assert_eq!(String::from(parsed), literal);
    }

    Ok(())
}
