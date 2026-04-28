use std::cmp::Ordering;

use semver::Version;

#[test]
fn prerelease_semver_ordering_is_pinned() -> Result<(), semver::Error> {
    let descending = [
        Version::parse("1.0.0")?,
        Version::parse("1.0.0-rc.2")?,
        Version::parse("1.0.0-rc.1")?,
        Version::parse("1.0.0-beta")?,
        Version::parse("1.0.0-alpha")?,
    ];

    for index in 0..(descending.len() - 1) {
        let higher = &descending[index];
        let lower = &descending[index + 1];

        assert_eq!(higher.partial_cmp(lower), Some(Ordering::Greater));
        assert_eq!(lower.partial_cmp(higher), Some(Ordering::Less));
    }

    for version in &descending {
        assert_eq!(version.partial_cmp(version), Some(Ordering::Equal));
    }

    Ok(())
}
