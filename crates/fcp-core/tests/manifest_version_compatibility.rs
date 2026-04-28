use std::cmp::Ordering;

use fcp_core::ConnectorVersion;

fn version(input: &str) -> Result<ConnectorVersion, semver::Error> {
    input.parse()
}

#[test]
fn same_major_manifest_versions_are_compatible_when_not_downgrades() -> Result<(), semver::Error> {
    let required = version("1.2.3")?;

    for candidate in ["1.2.3", "1.2.4", "1.3.0", "1.99.0"] {
        assert!(
            version(candidate)?.is_compatible_with(&required),
            "{candidate} should satisfy same-major required version {required}"
        );
    }

    Ok(())
}

#[test]
fn cross_major_manifest_versions_are_incompatible() -> Result<(), semver::Error> {
    let required = version("1.9.9")?;

    for candidate in ["0.99.99", "2.0.0", "2.0.0-alpha.1"] {
        assert!(
            !version(candidate)?.is_compatible_with(&required),
            "{candidate} must not satisfy cross-major required version {required}"
        );
    }

    assert!(!required.is_compatible_with(&version("2.0.0")?));

    Ok(())
}

#[test]
fn prerelease_manifest_versions_do_not_downgrade_stable_requirements() -> Result<(), semver::Error>
{
    let stable = version("1.0.0")?;

    for candidate in ["1.0.0-rc.2", "1.0.0-rc.1", "1.0.0-beta", "1.0.0-alpha"] {
        assert!(
            !version(candidate)?.is_compatible_with(&stable),
            "{candidate} must not satisfy stable required version {stable}"
        );
    }

    Ok(())
}

#[test]
fn prerelease_manifest_versions_preserve_semver_ordering() -> Result<(), semver::Error> {
    let alpha = version("1.0.0-alpha")?;
    let beta = version("1.0.0-beta")?;
    let rc1 = version("1.0.0-rc.1")?;
    let rc2 = version("1.0.0-rc.2")?;
    let stable = version("1.0.0")?;

    assert!(beta.is_compatible_with(&alpha));
    assert!(rc1.is_compatible_with(&beta));
    assert!(rc2.is_compatible_with(&rc1));
    assert!(stable.is_compatible_with(&rc2));

    assert!(!alpha.is_compatible_with(&beta));
    assert!(!beta.is_compatible_with(&rc1));
    assert!(!rc1.is_compatible_with(&rc2));
    assert!(!rc2.is_compatible_with(&stable));

    Ok(())
}

#[test]
fn connector_versions_compare_less_than_across_major_minor_patch() -> Result<(), semver::Error> {
    for (lower, higher, component) in [
        ("1.99.99", "2.0.0", "major"),
        ("1.1.99", "1.2.0", "minor"),
        ("1.2.3", "1.2.4", "patch"),
    ] {
        let lower = version(lower)?;
        let higher = version(higher)?;

        assert!(
            lower < higher,
            "{component} comparison should order lower version first"
        );
        assert_eq!(lower.cmp(&higher), Ordering::Less);
        assert_eq!(lower.partial_cmp(&higher), Some(Ordering::Less));
        assert_eq!(higher.cmp(&lower), Ordering::Greater);
        assert_eq!(higher.partial_cmp(&lower), Some(Ordering::Greater));
    }

    Ok(())
}

#[test]
fn connector_version_equality_is_pinned() -> Result<(), semver::Error> {
    let first = version("1.2.3")?;
    let second = version("1.2.3")?;

    assert_eq!(first, second);
    assert_eq!(first.cmp(&second), Ordering::Equal);
    assert_eq!(first.partial_cmp(&second), Some(Ordering::Equal));
    assert!(first <= second);
    assert!(first >= second);

    Ok(())
}

#[test]
fn connector_versions_sort_in_semver_order() -> Result<(), semver::Error> {
    let mut actual = vec![
        version("1.0.1")?,
        version("2.0.0")?,
        version("1.1.0")?,
        version("1.0.0")?,
        version("0.9.9")?,
    ];
    let expected = vec![
        version("0.9.9")?,
        version("1.0.0")?,
        version("1.0.1")?,
        version("1.1.0")?,
        version("2.0.0")?,
    ];

    actual.sort();

    assert_eq!(actual, expected);

    Ok(())
}
