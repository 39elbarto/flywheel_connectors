use fcp_anthropic::{connector::AnthropicConnector, error::AnthropicError};
use fcp_prelude::FcpError;
use fcp_testkit::{OperationContract, assert_operation_contracts};

#[fcp_async_core::runtime::test]
async fn anthropic_schema_operation_and_error_contracts_are_advertised() {
    let connector = AnthropicConnector::new();
    let introspection = connector
        .handle_introspect()
        .await
        .expect("anthropic introspection should serialize");

    assert_operation_contracts(
        &introspection,
        &[
            OperationContract {
                id: "anthropic.message",
                capability: "anthropic.message",
                required_input_fields: &["messages"],
                output_fields: &["id", "content", "model", "stop_reason", "usage", "cost_usd"],
            },
            OperationContract {
                id: "anthropic.message.stream",
                capability: "anthropic.message.stream",
                required_input_fields: &["messages"],
                output_fields: &["id", "content", "content_blocks", "streamed", "usage"],
            },
            OperationContract {
                id: "anthropic.get_usage",
                capability: "anthropic.get_usage",
                required_input_fields: &[],
                output_fields: &[
                    "total_input_tokens",
                    "total_output_tokens",
                    "total_cost_usd",
                    "requests_total",
                    "requests_error",
                ],
            },
        ],
    );

    assert!(matches!(
        AnthropicError::InvalidApiCredential.to_fcp_error(),
        FcpError::Unauthorized { code: 2001, .. }
    ));
    assert!(matches!(
        AnthropicError::RateLimited {
            retry_after_ms: 1_500,
        }
        .to_fcp_error(),
        FcpError::RateLimited {
            retry_after_ms: 1_500,
            ..
        }
    ));
    assert!(matches!(
        AnthropicError::Overloaded {
            retry_after_ms: 2_500,
        }
        .to_fcp_error(),
        FcpError::External {
            service,
            retryable: true,
            status_code: Some(529),
            ..
        } if service == "anthropic"
    ));
}
