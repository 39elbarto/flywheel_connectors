use fcp_github::{connector::GitHubConnector, error::GitHubError};
use fcp_prelude::FcpError;
use fcp_testkit::{OperationContract, assert_operation_contracts};

#[fcp_async_core::runtime::test]
async fn github_schema_operation_and_error_contracts_are_advertised() {
    let connector = GitHubConnector::new();
    let introspection = connector
        .handle_introspect()
        .await
        .expect("github introspection should serialize");

    assert_operation_contracts(
        &introspection,
        &[
            OperationContract {
                id: "github.create_issue",
                capability: "github.write",
                required_input_fields: &["owner", "repo", "title"],
                output_fields: &["issue"],
            },
            OperationContract {
                id: "github.get_repo",
                capability: "github.read",
                required_input_fields: &["owner", "repo"],
                output_fields: &["repository"],
            },
            OperationContract {
                id: "github.process_webhook",
                capability: "github.process_webhook",
                required_input_fields: &["payload", "signature_validated"],
                output_fields: &["event"],
            },
        ],
    );

    assert!(matches!(
        GitHubError::Unauthorized.to_fcp_error(),
        FcpError::Unauthorized { .. }
    ));
    assert!(matches!(
        GitHubError::RateLimited {
            retry_after_ms: 1_000,
        }
        .to_fcp_error(),
        FcpError::RateLimited {
            retry_after_ms: 1_000,
            ..
        }
    ));
    assert!(matches!(
        GitHubError::ValidationError {
            message: "missing title".into(),
        }
        .to_fcp_error(),
        FcpError::InvalidRequest { code: 1003, .. }
    ));
}
