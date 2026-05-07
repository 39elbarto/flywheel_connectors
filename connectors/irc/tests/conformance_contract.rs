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
