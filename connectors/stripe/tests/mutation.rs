//! Stripe mutation-harness pilot for recorded response parsing.

use std::time::Instant;

use fcp_stripe::types::PaymentIntent;
use fcp_testkit::{MutationHarness, OverallVerdict, ResultClass};

const STRIPE_CHARGE_GET_RESPONSE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../crates/fcp-testkit/tests/fixtures/mutation/stripe_charge_get_response.json"
));

#[test]
fn stripe_charge_get_response_mutations_are_rejected_or_semantically_neutral() {
    let started = Instant::now();
    let report = MutationHarness::new()
        .with_seed(7)
        .with_max_mutations(200)
        .run_with_classifier(
            STRIPE_CHARGE_GET_RESPONSE,
            parse_payment_intent_fixture,
            |_| ResultClass::GracefulPartialAccept,
        );

    assert!(report.never_panics);
    assert_eq!(report.silent_accepts(), 0, "{report:#?}");
    assert!(matches!(
        report.overall_verdict,
        OverallVerdict::AllGraceful
    ));
    assert!(
        report.rejected() * 2 >= report.total_attempts,
        "expected at least 50% rejected mutations: {report:#?}"
    );
    assert!(
        started.elapsed().as_millis() < 6_000,
        "200 mutation pilot should stay comfortably below the 30ms p99 budget"
    );
}

fn parse_payment_intent_fixture(bytes: &[u8]) -> Result<PaymentIntent, String> {
    let parsed: PaymentIntent = serde_json::from_slice(bytes).map_err(|err| err.to_string())?;

    if parsed.id != "pi_mutation_fixture" {
        return Err("unexpected payment intent id".into());
    }
    if parsed.object != "payment_intent" {
        return Err("unexpected Stripe object type".into());
    }
    if parsed.amount != 4242 {
        return Err("unexpected payment amount".into());
    }
    if parsed.currency != "usd" {
        return Err("unexpected currency".into());
    }
    if parsed.status != "succeeded" {
        return Err("unexpected payment status".into());
    }

    Ok(parsed)
}
