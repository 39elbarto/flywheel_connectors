#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    clippy::unwrap_used
)]

use std::collections::BTreeMap;

use fcp_email_generic::EmailGenericConnector;
use fcp_email_generic::error::EmailGenericError;
use fcp_prelude::{ApprovalMode, IdempotencyClass, RiskLevel, SafetyTier};
use toml::Value;

const MANIFEST: &str = include_str!("../manifest.toml");
const OP_HEALTH: &str = "email_generic.health";
const OP_LIST_MAILBOXES: &str = "email_generic.list_mailboxes";
const OP_SEARCH_MESSAGES: &str = "email_generic.search_messages";
const OP_SEND_MESSAGE: &str = "email_generic.send_message";
const CAP_READ: &str = "email_generic.read";
const CAP_WRITE: &str = "email_generic.write";

#[test]
fn operation_info_matches_email_generic_contract() {
    let operations = EmailGenericConnector::operations_info();
    let by_id = operations
        .iter()
        .map(|operation| (operation.id.as_str(), operation))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(by_id.len(), 4);
    assert!(by_id.contains_key(OP_HEALTH));
    assert!(by_id.contains_key(OP_LIST_MAILBOXES));
    assert!(by_id.contains_key(OP_SEARCH_MESSAGES));
    assert!(by_id.contains_key(OP_SEND_MESSAGE));

    for op_id in [OP_HEALTH, OP_LIST_MAILBOXES, OP_SEARCH_MESSAGES] {
        let operation = by_id[op_id];
        assert_eq!(operation.capability.as_str(), CAP_READ);
        assert_eq!(operation.risk_level, RiskLevel::Low);
        assert_eq!(operation.safety_tier, SafetyTier::Safe);
        assert_eq!(operation.idempotency, IdempotencyClass::Strict);
        assert_eq!(operation.requires_approval, Some(ApprovalMode::None));
        assert!(
            operation
                .description
                .as_ref()
                .is_some_and(|value| !value.trim().is_empty()),
            "{op_id} should carry operator-facing description"
        );
        assert!(
            !operation.ai_hints.when_to_use.trim().is_empty(),
            "{op_id} should carry when_to_use hint"
        );
    }

    let send = by_id[OP_SEND_MESSAGE];
    assert_eq!(send.capability.as_str(), CAP_WRITE);
    assert_eq!(send.risk_level, RiskLevel::Medium);
    assert_eq!(send.safety_tier, SafetyTier::Risky);
    assert_eq!(send.idempotency, IdempotencyClass::None);
    assert_eq!(send.requires_approval, Some(ApprovalMode::None));
    assert!(
        send.ai_hints
            .common_mistakes
            .iter()
            .any(|hint| hint.contains("recipient")),
        "send operation should warn about recipient requirement"
    );
}

#[test]
fn operation_schemas_are_strict_and_cover_required_fields() {
    let operations = EmailGenericConnector::operations_info();
    let by_id = operations
        .iter()
        .map(|operation| (operation.id.as_str(), operation))
        .collect::<BTreeMap<_, _>>();

    for op_id in [OP_HEALTH, OP_LIST_MAILBOXES] {
        let input_schema = &by_id[op_id].input_schema;
        assert_eq!(input_schema["type"], "object");
        assert_eq!(input_schema["additionalProperties"], false);
        assert!(input_schema.get("required").is_none());
    }

    let search_input = &by_id[OP_SEARCH_MESSAGES].input_schema;
    assert_eq!(search_input["type"], "object");
    assert_eq!(search_input["additionalProperties"], false);
    assert_eq!(search_input["properties"]["mailbox"]["minLength"], 1);
    assert_eq!(search_input["properties"]["query"]["minLength"], 1);
    assert_eq!(search_input["required"][0], "mailbox");
    assert_eq!(search_input["required"][1], "query");

    let send_input = &by_id[OP_SEND_MESSAGE].input_schema;
    assert_eq!(send_input["type"], "object");
    assert_eq!(send_input["additionalProperties"], false);
    assert_eq!(send_input["properties"]["to"]["minItems"], 1);
    assert_eq!(send_input["properties"]["to"]["items"]["minLength"], 1);
    assert_eq!(send_input["required"][0], "to");
    assert_eq!(send_input["required"][1], "subject");
    assert_eq!(send_input["required"][2], "body");

    let health_output = &by_id[OP_HEALTH].output_schema;
    for required in [
        "status",
        "imap_host",
        "smtp_host",
        "manifest_hash",
        "monitor_policy",
        "inbound_monitor",
    ] {
        assert!(
            health_output["required"]
                .as_array()
                .expect("required should be an array")
                .iter()
                .any(|value| value == required),
            "health output should require {required}"
        );
    }
    assert_eq!(
        health_output["properties"]["inbound_monitor"]["properties"]["status"]["enum"][0],
        "deferred"
    );

    let list_output = &by_id[OP_LIST_MAILBOXES].output_schema;
    assert_eq!(list_output["properties"]["mailboxes"]["type"], "array");

    let search_output = &by_id[OP_SEARCH_MESSAGES].output_schema;
    assert_eq!(search_output["properties"]["uids"]["type"], "array");
    assert_eq!(search_output["properties"]["uids"]["items"]["minimum"], 0);

    let send_output = &by_id[OP_SEND_MESSAGE].output_schema;
    assert_eq!(send_output["properties"]["status"]["enum"][0], "sent");
    assert_eq!(send_output["properties"]["cc"]["type"], "array");
}

#[test]
fn manifest_declares_matching_operation_suffixes_and_capabilities() {
    for (section, capability) in [
        ("health", CAP_READ),
        ("list_mailboxes", CAP_READ),
        ("search_messages", CAP_READ),
        ("send_message", CAP_WRITE),
    ] {
        let section_header = format!("[provides.operations.{section}]");
        let start = MANIFEST
            .find(&section_header)
            .expect("manifest operation section should exist");
        let rest = &MANIFEST[start..];
        let next_section = rest.find("\n[").unwrap_or(rest.len());
        let section_text = &rest[..next_section];
        assert!(
            section_text.contains(&format!("capability = \"{capability}\"")),
            "{section} should declare {capability}"
        );
        assert!(
            section_text.contains("safety_tier"),
            "{section} should declare safety tier"
        );
        assert!(
            section_text.contains("idempotency"),
            "{section} should declare idempotency"
        );
    }

    assert!(MANIFEST.contains("id = \"fcp.email-generic\""));
    assert!(MANIFEST.contains("home = \"z:private\""));
    assert!(MANIFEST.contains("network.dns"));
    assert!(MANIFEST.contains("network.outbound"));
    assert!(MANIFEST.contains("network.listen"));
}

#[test]
fn manifest_declares_runtime_scoped_network_constraints() {
    let manifest =
        toml::from_str::<Value>(MANIFEST).expect("email-generic manifest should parse as TOML");

    for section in ["health", "list_mailboxes", "search_messages"] {
        let constraints = network_constraints(&manifest, section);
        assert_eq!(
            string_list(constraints, "host_allow"),
            ["${email_imap_host}"]
        );
        assert_eq!(integer_list(constraints, "port_allow"), [143, 993]);
        assert_common_mail_constraints(constraints);
        assert_eq!(integer(constraints, "max_response_bytes"), 1_048_576);
    }

    let smtp = network_constraints(&manifest, "send_message");
    assert_eq!(string_list(smtp, "host_allow"), ["${email_smtp_host}"]);
    assert_eq!(integer_list(smtp, "port_allow"), [25, 465, 587]);
    assert_common_mail_constraints(smtp);
    assert_eq!(integer(smtp, "max_response_bytes"), 65_536);
}

fn network_constraints<'a>(manifest: &'a Value, section: &str) -> &'a toml::value::Table {
    manifest
        .get("provides")
        .and_then(Value::as_table)
        .and_then(|provides| provides.get("operations"))
        .and_then(Value::as_table)
        .and_then(|operations| operations.get(section))
        .and_then(Value::as_table)
        .and_then(|operation| operation.get("network_constraints"))
        .and_then(Value::as_table)
        .unwrap_or_else(|| panic!("{section} should declare network_constraints"))
}

fn string_list<'a>(table: &'a toml::value::Table, key: &str) -> Vec<&'a str> {
    table
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} should be an array"))
        .iter()
        .map(|value| {
            value
                .as_str()
                .unwrap_or_else(|| panic!("{key} entries should be strings"))
        })
        .collect()
}

fn integer_list(table: &toml::value::Table, key: &str) -> Vec<i64> {
    table
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} should be an array"))
        .iter()
        .map(|value| {
            value
                .as_integer()
                .unwrap_or_else(|| panic!("{key} entries should be integers"))
        })
        .collect()
}

fn boolean(table: &toml::value::Table, key: &str) -> bool {
    table
        .get(key)
        .and_then(Value::as_bool)
        .unwrap_or_else(|| panic!("{key} should be a boolean"))
}

fn integer(table: &toml::value::Table, key: &str) -> i64 {
    table
        .get(key)
        .and_then(Value::as_integer)
        .unwrap_or_else(|| panic!("{key} should be an integer"))
}

fn assert_common_mail_constraints(constraints: &toml::value::Table) {
    assert!(integer_list(constraints, "ip_allow").is_empty());
    assert!(integer_list(constraints, "cidr_deny").is_empty());
    assert!(!boolean(constraints, "deny_localhost"));
    assert!(!boolean(constraints, "deny_private_ranges"));
    assert!(!boolean(constraints, "deny_tailnet_ranges"));
    assert!(boolean(constraints, "require_sni"));
    assert!(string_list(constraints, "spki_pins").is_empty());
    assert!(!boolean(constraints, "deny_ip_literals"));
    assert!(boolean(constraints, "require_host_canonicalization"));
    assert_eq!(integer(constraints, "dns_max_ips"), 16);
    assert_eq!(integer(constraints, "max_redirects"), 0);
    assert_eq!(integer(constraints, "connect_timeout_ms"), 10_000);
    assert_eq!(integer(constraints, "total_timeout_ms"), 30_000);
}

#[test]
fn error_mapping_preserves_retry_and_request_boundaries() {
    let config = EmailGenericError::Config("bad config".into()).to_fcp_error();
    assert_eq!(config.error_code(), "FCP-1003");

    let address = EmailGenericError::Address("missing at".into()).to_fcp_error();
    assert_eq!(address.error_code(), "FCP-1005");

    let io = EmailGenericError::Io(std::io::Error::new(
        std::io::ErrorKind::ConnectionReset,
        "reset",
    ))
    .to_fcp_error();
    assert!(matches!(
        io,
        fcp_prelude::FcpError::External {
            retryable: true,
            ..
        }
    ));

    let smtp = EmailGenericError::Smtp("relay denied".into()).to_fcp_error();
    assert!(matches!(
        smtp,
        fcp_prelude::FcpError::External {
            retryable: false,
            ..
        }
    ));
}
