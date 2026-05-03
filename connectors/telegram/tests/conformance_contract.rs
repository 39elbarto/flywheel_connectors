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
