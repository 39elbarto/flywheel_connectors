use fcp_github::{connector::GitHubConnector, error::GitHubError};
use fcp_manifest::ConnectorManifest;
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

#[test]
fn github_manifest_declares_no_egress_for_process_webhook() {
    let manifest_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("manifest.toml");
    let raw = std::fs::read_to_string(&manifest_path).expect("read manifest");
    let manifest = ConnectorManifest::parse_str(&raw).expect("manifest should validate");
    let operation = manifest
        .provides
        .operations
        .get("github.process_webhook")
        .expect("process_webhook operation");
    let constraints = operation
        .network_constraints
        .as_ref()
        .expect("process_webhook network constraints");

    assert_eq!(constraints.host_allow.as_slice(), ["none.invalid"]);
    assert_eq!(constraints.port_allow.as_slice(), [0]);
    assert!(constraints.ip_allow.is_empty());
    assert!(constraints.cidr_deny.is_empty());
    assert!(constraints.deny_localhost);
    assert!(constraints.deny_private_ranges);
    assert!(constraints.deny_tailnet_ranges);
    assert!(!constraints.require_sni);
    assert!(constraints.spki_pins.is_empty());
    assert!(constraints.deny_ip_literals);
    assert!(constraints.require_host_canonicalization);
    assert_eq!(constraints.dns_max_ips, 0);
    assert_eq!(constraints.max_redirects, 0);
    assert_eq!(constraints.connect_timeout_ms, 1_000);
    assert_eq!(constraints.total_timeout_ms, 15_000);
    assert_eq!(constraints.max_response_bytes, 1_048_576);
}
