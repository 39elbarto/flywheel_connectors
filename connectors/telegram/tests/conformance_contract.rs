use fcp_prelude::FcpError;
use fcp_telegram::{connector::TelegramConnector, error::TelegramError};
use fcp_testkit::{OperationContract, assert_operation_contracts};

#[fcp_async_core::runtime::test]
async fn telegram_schema_operation_and_error_contracts_are_advertised() {
    let connector = TelegramConnector::new();
    let introspection = connector
        .handle_introspect()
        .await
        .expect("telegram introspection should serialize");

    assert_operation_contracts(
        &introspection,
        &[
            OperationContract {
                id: "telegram.send_message",
                capability: "telegram.send",
                required_input_fields: &["chat_id", "text"],
                output_fields: &["message_id", "chat_id"],
            },
            OperationContract {
                id: "telegram.get_file",
                capability: "telegram.read",
                required_input_fields: &["file_id"],
                output_fields: &["file_id", "file_path", "file_size"],
            },
            OperationContract {
                id: "telegram.answer_callback_query",
                capability: "telegram.send",
                required_input_fields: &["callback_query_id"],
                output_fields: &["success"],
            },
            OperationContract {
                id: "telegram.send_chat_action",
                capability: "telegram.send",
                required_input_fields: &["chat_id", "action"],
                output_fields: &["success"],
            },
            OperationContract {
                id: "telegram.set_message_reaction",
                capability: "telegram.send",
                required_input_fields: &["chat_id", "message_id"],
                output_fields: &["success"],
            },
            OperationContract {
                id: "telegram.set_webhook",
                capability: "telegram.webhook",
                required_input_fields: &["url"],
                output_fields: &["success", "url", "secret_token_configured"],
            },
            OperationContract {
                id: "telegram.delete_webhook",
                capability: "telegram.webhook",
                required_input_fields: &[],
                output_fields: &["success"],
            },
            OperationContract {
                id: "telegram.get_webhook_info",
                capability: "telegram.webhook",
                required_input_fields: &[],
                output_fields: &["url", "has_custom_certificate", "pending_update_count"],
            },
            OperationContract {
                id: "telegram.ingest_webhook_update",
                capability: "telegram.webhook",
                required_input_fields: &["payload", "secret_token"],
                output_fields: &["accepted", "event_emitted", "update_id", "secret_verified"],
            },
        ],
    );

    assert!(matches!(
        TelegramError::Api {
            code: 429,
            description: "too many requests".into(),
        }
        .to_fcp_error(),
        FcpError::RateLimited {
            retry_after_ms: 30_000,
            ..
        }
    ));
    assert!(matches!(
        TelegramError::Api {
            code: 403,
            description: "forbidden".into(),
        }
        .to_fcp_error(),
        FcpError::CapabilityDenied { .. }
    ));
    assert!(matches!(
        TelegramError::InvalidChatId("missing".into()).to_fcp_error(),
        FcpError::InvalidRequest { code: 1003, .. }
    ));
}
