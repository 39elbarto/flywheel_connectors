use fcp_prelude::FcpError;
use fcp_stripe::{connector::StripeConnector, error::StripeError};
use fcp_testkit::{OperationContract, assert_operation_contracts};

#[fcp_async_core::runtime::test]
async fn stripe_schema_operation_and_error_contracts_are_advertised() {
    let connector = StripeConnector::new();
    let introspection = connector
        .handle_introspect()
        .await
        .expect("stripe introspection should serialize");

    assert_operation_contracts(
        &introspection,
        &[
            OperationContract {
                id: "stripe.create_customer",
                capability: "stripe.write",
                required_input_fields: &["email"],
                output_fields: &["customer", "audit"],
            },
            OperationContract {
                id: "stripe.create_payment_intent",
                capability: "stripe.payment",
                required_input_fields: &["amount", "currency"],
                output_fields: &["payment_intent"],
            },
            OperationContract {
                id: "stripe.ingest_webhook_event",
                capability: "stripe.webhook",
                required_input_fields: &["payload", "stripe_signature"],
                output_fields: &["event", "delivery"],
            },
        ],
    );

    assert!(matches!(
        StripeError::Unauthorized.to_fcp_error(),
        FcpError::Unauthorized { .. }
    ));
    assert!(matches!(
        StripeError::RateLimited {
            retry_after_ms: 1_500,
        }
        .to_fcp_error(),
        FcpError::RateLimited {
            retry_after_ms: 1_500,
            ..
        }
    ));
    assert!(matches!(
        StripeError::Api {
            message: "card declined".into(),
            status_code: Some(402),
            error_type: Some("card_error".into()),
        }
        .to_fcp_error(),
        FcpError::External {
            service,
            retryable: false,
            ..
        } if service == "stripe"
    ));
}
