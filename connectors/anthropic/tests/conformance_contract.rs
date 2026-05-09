use fcp_anthropic::{connector::AnthropicConnector, error::AnthropicError};
use fcp_manifest::ConnectorManifest;
use fcp_prelude::FcpError;
use fcp_testkit::{OperationContract, assert_operation_contracts};

#[test]
fn manifest_ai_hints_cover_all_anthropic_operations() {
    let manifest = ConnectorManifest::parse_str(include_str!("../manifest.toml"))
        .expect("anthropic manifest should validate");

    for (operation_id, operation) in &manifest.provides.operations {
        let hints = &operation.ai_hints;
        assert!(
            !hints.when_to_use.trim().is_empty(),
            "{operation_id} missing ai_hints.when_to_use"
        );
        assert!(
            !hints.common_mistakes.is_empty()
                && hints
                    .common_mistakes
                    .iter()
                    .all(|mistake| !mistake.trim().is_empty()),
            "{operation_id} missing ai_hints.common_mistakes"
        );
        assert!(
            !hints.examples.is_empty(),
            "{operation_id} missing ai_hints.examples"
        );
    }
}

#[test]
fn manifest_declares_strict_per_operation_network_constraints() {
    let manifest = ConnectorManifest::parse_str(include_str!("../manifest.toml"))
        .expect("anthropic manifest should validate");
    let provider_ops = [
        "anthropic.chat",
        "anthropic.message",
        "anthropic.message.stream",
    ];
    let local_ops = [
        "anthropic.get_usage",
        "anthropic.auth.list_methods",
        "anthropic.auth.refresh_oauth",
        "anthropic.models.normalize",
    ];

    for operation_id in provider_ops {
        let operation = manifest
            .provides
            .operations
            .get(operation_id)
            .unwrap_or_else(|| panic!("missing {operation_id} operation"));
        let constraints = operation
            .network_constraints
            .as_ref()
            .unwrap_or_else(|| panic!("{operation_id} missing network_constraints"));
        assert_eq!(constraints.host_allow.as_slice(), ["api.anthropic.com"]);
        assert_eq!(constraints.port_allow.as_slice(), [443]);
        assert!(constraints.ip_allow.is_empty());
        assert!(constraints.cidr_deny.is_empty());
        assert!(constraints.deny_localhost);
        assert!(constraints.deny_private_ranges);
        assert!(constraints.deny_tailnet_ranges);
        assert!(constraints.require_sni);
        assert!(constraints.spki_pins.is_empty());
        assert!(constraints.deny_ip_literals);
        assert!(constraints.require_host_canonicalization);
        assert_eq!(constraints.dns_max_ips, 16);
        assert_eq!(constraints.max_redirects, 5);
        assert_eq!(constraints.connect_timeout_ms, 10_000);
        assert_eq!(constraints.total_timeout_ms, 120_000);
        assert_eq!(constraints.max_response_bytes, 10_485_760);
    }

    for operation_id in local_ops {
        let operation = manifest
            .provides
            .operations
            .get(operation_id)
            .unwrap_or_else(|| panic!("missing {operation_id} operation"));
        let constraints = operation
            .network_constraints
            .as_ref()
            .unwrap_or_else(|| panic!("{operation_id} missing network_constraints"));
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
        assert_eq!(constraints.connect_timeout_ms, 10_000);
        assert_eq!(constraints.total_timeout_ms, 30_000);
        assert_eq!(constraints.max_response_bytes, 65_536);
    }

    assert_eq!(
        manifest.provides.operations.len(),
        provider_ops.len() + local_ops.len(),
        "update network constraint assertions when Anthropic operations change"
    );
}

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
