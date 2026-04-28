use std::{net::IpAddr, str::FromStr};

type ParseResult = Result<(), std::net::AddrParseError>;

#[test]
fn ip_addr_display_from_str_roundtrips_representative_inputs() -> ParseResult {
    let cases = [
        ("ipv4 loopback", "127.0.0.1", "127.0.0.1"),
        ("ipv6 loopback", "::1", "::1"),
        ("ipv4 link-local", "169.254.10.20", "169.254.10.20"),
        ("ipv6 link-local", "fe80::1", "fe80::1"),
        ("ipv4 public", "8.8.8.8", "8.8.8.8"),
        (
            "ipv6 public",
            "2001:4860:4860::8888",
            "2001:4860:4860::8888",
        ),
        (
            "ipv4-mapped ipv6",
            "::ffff:192.0.2.128",
            "::ffff:192.0.2.128",
        ),
    ];

    for (label, input, expected_display) in cases {
        let parsed = IpAddr::from_str(input)?;
        let displayed = parsed.to_string();
        let roundtripped = IpAddr::from_str(&displayed)?;

        assert_eq!(
            displayed, expected_display,
            "{label}: Display output should stay canonical"
        );
        assert_eq!(
            roundtripped, parsed,
            "{label}: Display output should parse back to the same IpAddr"
        );
    }

    Ok(())
}
