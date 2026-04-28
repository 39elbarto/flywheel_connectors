use fcp_core::OAuthRecipe;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct OauthFlowKindCase {
    value: OAuthRecipe,
    tag: &'static str,
}

fn cases() -> Vec<OauthFlowKindCase> {
    vec![
        OauthFlowKindCase {
            value: OAuthRecipe::AuthorizationCodePkce {
                authorization_url: String::from("https://auth.example/authorize"),
                token_url: String::from("https://auth.example/token"),
                scopes: Vec::new(),
                auto_browser: false,
                callback_port: 53682,
            },
            tag: "authorization_code_pkce",
        },
        OauthFlowKindCase {
            value: OAuthRecipe::DeviceCode {
                device_authorization_url: String::from("https://auth.example/device"),
                token_url: String::from("https://auth.example/token"),
                scopes: Vec::new(),
                poll_interval_seconds: 5,
            },
            tag: "device_code",
        },
        OauthFlowKindCase {
            value: OAuthRecipe::ClientCredentials {
                token_url: String::from("https://auth.example/token"),
                scopes: Vec::new(),
            },
            tag: "client_credentials",
        },
    ]
}

fn oauth_flow_kind_tag(flow: &OAuthRecipe) -> &'static str {
    match flow {
        OAuthRecipe::AuthorizationCodePkce { .. } => "authorization_code_pkce",
        OAuthRecipe::DeviceCode { .. } => "device_code",
        OAuthRecipe::ClientCredentials { .. } => "client_credentials",
    }
}

fn cbor_type_tag(value: &ciborium::Value) -> Option<&str> {
    let ciborium::Value::Map(entries) = value else {
        return None;
    };

    entries.iter().find_map(|(key, value)| match (key, value) {
        (ciborium::Value::Text(key), ciborium::Value::Text(tag)) if key == "type" => {
            Some(tag.as_str())
        }
        _ => None,
    })
}

#[test]
fn oauth_flow_kind_json_tags_are_stable_and_roundtrip() -> TestResult {
    for case in cases() {
        let encoded = serde_json::to_value(&case.value)?;
        assert_eq!(
            encoded.get("type").and_then(serde_json::Value::as_str),
            Some(case.tag)
        );

        let decoded: OAuthRecipe = serde_json::from_value(encoded)?;
        assert_eq!(oauth_flow_kind_tag(&decoded), case.tag);
    }

    Ok(())
}

#[test]
fn oauth_flow_kind_cbor_tags_are_stable_and_roundtrip() -> TestResult {
    for case in cases() {
        let mut encoded = Vec::new();
        ciborium::into_writer(&case.value, &mut encoded)?;

        let cbor_value: ciborium::Value = ciborium::from_reader(encoded.as_slice())?;
        assert_eq!(cbor_type_tag(&cbor_value), Some(case.tag));

        let decoded: OAuthRecipe = ciborium::from_reader(encoded.as_slice())?;
        assert_eq!(oauth_flow_kind_tag(&decoded), case.tag);
    }

    Ok(())
}
