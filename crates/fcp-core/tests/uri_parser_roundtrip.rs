use std::str::FromStr;

use fcp_core::util::SafeUri;

#[derive(Debug, Clone, Copy)]
struct SafeUriCase {
    raw: &'static str,
    scheme: &'static str,
    host: Option<&'static str>,
    path: &'static str,
    query: Option<&'static str>,
}

fn safe_uri_cases() -> [SafeUriCase; 4] {
    [
        SafeUriCase {
            raw: "https://api.example.com/v1/messages?limit=50&cursor=abc",
            scheme: "https",
            host: Some("api.example.com"),
            path: "/v1/messages",
            query: Some("limit=50&cursor=abc"),
        },
        SafeUriCase {
            raw: "http://localhost:8080/healthz?ready=true",
            scheme: "http",
            host: Some("localhost"),
            path: "/healthz",
            query: Some("ready=true"),
        },
        SafeUriCase {
            raw: "file:///var/lib/fcp/state.db",
            scheme: "file",
            host: None,
            path: "/var/lib/fcp/state.db",
            query: None,
        },
        SafeUriCase {
            raw: "fcp+connector://calendar/events/primary?zone=z%3Awork",
            scheme: "fcp+connector",
            host: Some("calendar"),
            path: "/events/primary",
            query: Some("zone=z%3Awork"),
        },
    ]
}

#[test]
fn safe_uri_shapes_roundtrip_through_display_and_from_str() -> Result<(), Box<dyn std::error::Error>>
{
    for case in safe_uri_cases() {
        let parsed = SafeUri::from_str(case.raw)?;
        let displayed = parsed.to_string();
        let reparsed = SafeUri::from_str(&displayed)?;

        assert_eq!(displayed, case.raw);
        assert_eq!(reparsed, parsed);
    }

    Ok(())
}

#[test]
fn safe_uri_shapes_preserve_scheme_host_path_and_query() -> Result<(), Box<dyn std::error::Error>> {
    for case in safe_uri_cases() {
        let parsed = SafeUri::from_str(case.raw)?;

        assert_eq!(parsed.scheme(), case.scheme);
        assert_eq!(parsed.host(), case.host);
        assert_eq!(parsed.path(), case.path);
        assert_eq!(parsed.query(), case.query);
    }

    Ok(())
}
