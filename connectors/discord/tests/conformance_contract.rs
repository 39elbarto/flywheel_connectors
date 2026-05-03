use fcp_discord::{DiscordConnector, DiscordError};
use fcp_prelude::FcpError;
use fcp_testkit::{OperationContract, assert_operation_contracts};

#[fcp_async_core::runtime::test]
async fn discord_schema_operation_and_error_contracts_are_advertised() {
    let connector = DiscordConnector::new();
    let introspection = connector
        .handle_introspect()
        .await
        .expect("discord introspection should serialize");

    assert_operation_contracts(
        &introspection,
        &[
            OperationContract {
                id: "discord.send_message",
                capability: "discord.send",
                required_input_fields: &["channel_id"],
                output_fields: &["id", "channel_id", "content"],
            },
            OperationContract {
                id: "discord.add_reaction",
                capability: "discord.react",
                required_input_fields: &["channel_id", "message_id", "emoji"],
                output_fields: &["added"],
            },
            OperationContract {
                id: "discord.create_thread",
                capability: "discord.threads",
                required_input_fields: &["channel_id", "message_id", "name"],
                output_fields: &["id", "name", "type"],
            },
        ],
    );

    assert!(matches!(
        DiscordError::Api {
            code: 429,
            message: "rate limited".into(),
            retry_after: Some(2.5),
        }
        .to_fcp_error(),
        FcpError::RateLimited {
            retry_after_ms: 2_500,
            ..
        }
    ));
    assert!(matches!(
        DiscordError::InvalidInput("bad snowflake".into()).to_fcp_error(),
        FcpError::InvalidRequest { code: 1005, .. }
    ));
    assert!(matches!(
        DiscordError::Gateway("session dropped".into()).to_fcp_error(),
        FcpError::ConnectorUnavailable { code: 5001, .. }
    ));
}
