use fcp_irc::{
    IrcConnector,
    error::IrcError,
    types::{
        CAP_CHANNELS_WRITE, CAP_HEALTH_READ, CAP_MESSAGES_READ, CAP_MESSAGES_WRITE, OP_HEALTH,
        OP_JOIN_CHANNEL, OP_SAMPLE_TRANSCRIPT, OP_SEND_MESSAGE,
    },
};
use fcp_prelude::{FcpConnector, FcpError};
use fcp_testkit::{OperationContract, assert_operation_contracts};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

#[test]
fn irc_schema_operation_and_error_contracts_are_advertised() {
    let connector = IrcConnector::new();
    let introspection =
        serde_json::to_value(connector.introspect()).expect("irc introspection should serialize");

    assert_operation_contracts(
        &introspection,
        &[
            OperationContract {
                id: OP_SEND_MESSAGE,
                capability: CAP_MESSAGES_WRITE,
                required_input_fields: &["target", "message"],
                output_fields: &["status", "target", "transcript"],
            },
            OperationContract {
                id: OP_JOIN_CHANNEL,
                capability: CAP_CHANNELS_WRITE,
                required_input_fields: &["channel"],
                output_fields: &["status", "channel", "transcript", "events", "identity"],
            },
            OperationContract {
                id: OP_SAMPLE_TRANSCRIPT,
                capability: CAP_MESSAGES_READ,
                required_input_fields: &["channel"],
                output_fields: &["channel", "lines", "events", "identity"],
            },
            OperationContract {
                id: OP_HEALTH,
                capability: CAP_HEALTH_READ,
                required_input_fields: &[],
                output_fields: &[
                    "status",
                    "server",
                    "port",
                    "tls",
                    "nick",
                    "transcript",
                    "events",
                    "identity",
                    "manifest_hash",
                ],
            },
        ],
    );

    let operations = introspection["operations"]
        .as_array()
        .expect("operations should be an array");
    assert_eq!(operations.len(), 4);
    for operation in operations {
        assert!(
            operation["summary"]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "operation should advertise a non-empty summary: {operation:?}"
        );
        assert_eq!(operation["input_schema"]["type"], "object");
        assert_eq!(operation["output_schema"]["type"], "object");
        assert!(
            operation["risk_level"].as_str().is_some(),
            "operation should advertise risk_level: {operation:?}"
        );
        assert!(
            operation["safety_tier"].as_str().is_some(),
            "operation should advertise safety_tier: {operation:?}"
        );
        assert!(
            operation["idempotency"].as_str().is_some(),
            "operation should advertise idempotency: {operation:?}"
        );
        assert!(
            operation["ai_hints"]["when_to_use"]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
            "operation should advertise when_to_use hints: {operation:?}"
        );
        assert!(
            operation["ai_hints"]["common_mistakes"]
                .as_array()
                .is_some_and(|value| !value.is_empty()),
            "operation should advertise common_mistakes hints: {operation:?}"
        );
    }

    assert!(matches!(
        IrcError::Timeout("read deadline".into()).to_fcp_error(),
        FcpError::UpstreamTimeout { .. }
    ));
    assert!(matches!(
        IrcError::Config("missing server".into()).to_fcp_error(),
        FcpError::InvalidRequest { code: 1001, .. }
    ));
    assert!(matches!(
        IrcError::InvalidInput("target is required".into()).to_fcp_error(),
        FcpError::InvalidRequest { code: 1005, .. }
    ));
    assert!(matches!(
        IrcError::Tls("certificate expired".into()).to_fcp_error(),
        FcpError::External {
            service,
            retryable: true,
            ..
        } if service == "irc"
    ));
}

#[test]
fn manifest_declares_runtime_scoped_per_operation_network_constraints() {
    let manifest: toml::Value =
        toml::from_str(MANIFEST_TOML).expect("IRC manifest should parse as TOML");
    let operations = manifest
        .get("provides")
        .and_then(|value| value.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("IRC manifest should declare operations");

    for operation_id in [
        OP_SEND_MESSAGE,
        OP_JOIN_CHANNEL,
        OP_SAMPLE_TRANSCRIPT,
        OP_HEALTH,
    ] {
        let operation = operations
            .get(operation_id)
            .expect("IRC operation should be declared in manifest");
        let network_constraints = operation
            .get("network_constraints")
            .expect("IRC operation should declare network_constraints");

        assert_string_array_eq(
            network_constraints,
            "host_allow",
            &["${irc_server_host}"],
            operation_id,
        );
        assert_integer_array_eq(
            network_constraints,
            "port_allow",
            &[6667, 6697],
            operation_id,
        );
        assert_bool(network_constraints, "require_sni", true, operation_id);
        assert_bool(network_constraints, "deny_localhost", false, operation_id);
        assert_bool(
            network_constraints,
            "deny_private_ranges",
            false,
            operation_id,
        );
        assert_bool(
            network_constraints,
            "deny_tailnet_ranges",
            false,
            operation_id,
        );
        assert_bool(network_constraints, "deny_ip_literals", false, operation_id);
        assert_bool(
            network_constraints,
            "require_host_canonicalization",
            true,
            operation_id,
        );
        assert_integer(network_constraints, "max_redirects", 0, operation_id);
        assert_integer(
            network_constraints,
            "connect_timeout_ms",
            10000,
            operation_id,
        );
        assert_integer(network_constraints, "total_timeout_ms", 30000, operation_id);
    }
}

fn assert_string_array_eq(
    network_constraints: &toml::Value,
    field: &str,
    expected: &[&str],
    operation_id: &str,
) {
    let actual = network_constraints
        .get(field)
        .expect("network_constraints field should be declared")
        .as_array()
        .expect("network_constraints field should be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("network_constraints array entries should be strings")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual, expected,
        "{operation_id} network_constraints.{field}"
    );
}

fn assert_integer_array_eq(
    network_constraints: &toml::Value,
    field: &str,
    expected: &[i64],
    operation_id: &str,
) {
    let actual = network_constraints
        .get(field)
        .expect("network_constraints field should be declared")
        .as_array()
        .expect("network_constraints field should be an array")
        .iter()
        .map(|value| {
            value
                .as_integer()
                .expect("network_constraints array entries should be integers")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual, expected,
        "{operation_id} network_constraints.{field}"
    );
}

fn assert_bool(network_constraints: &toml::Value, field: &str, expected: bool, operation_id: &str) {
    let actual = network_constraints
        .get(field)
        .expect("network_constraints field should be declared")
        .as_bool()
        .expect("network_constraints field should be a bool");
    assert_eq!(
        actual, expected,
        "{operation_id} network_constraints.{field}"
    );
}

fn assert_integer(
    network_constraints: &toml::Value,
    field: &str,
    expected: i64,
    operation_id: &str,
) {
    let actual = network_constraints
        .get(field)
        .expect("network_constraints field should be declared")
        .as_integer()
        .expect("network_constraints field should be an integer");
    assert_eq!(
        actual, expected,
        "{operation_id} network_constraints.{field}"
    );
}
