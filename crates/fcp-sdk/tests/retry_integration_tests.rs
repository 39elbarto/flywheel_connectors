//! Integration tests for retry taxonomy helpers with a fake HTTP server.

use std::time::Duration;

use fcp_sdk::FcpError;
use fcp_sdk::retry::{RetryDecision, RetryPolicy, map_external_error};
use reqwest::Client;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn retry_policy_example_with_wiremock() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/rate_limit"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "2"))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/unavailable"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let client = Client::new();
    let policy = RetryPolicy::new().with_jitter_enabled(false);

    let response = client
        .get(format!("{}/rate_limit", server.uri()))
        .send()
        .await
        .expect("rate_limit response");
    let retry_after = retry_after_from_response(&response);
    let status = response.status().as_u16();

    let (decision, err) =
        map_external_error("wiremock", Some(status), "Too Many Requests", retry_after);
    assert_eq!(decision, RetryDecision::After(Duration::from_secs(2)));
    assert!(
        matches!(&err, FcpError::RateLimited { retry_after_ms, .. } if *retry_after_ms == 2_000),
        "expected rate limited error, got {err:?}"
    );
    let delay = policy.next_delay(0, decision, None).expect("delay");
    assert_eq!(delay, Duration::from_secs(2));

    let response = client
        .get(format!("{}/unavailable", server.uri()))
        .send()
        .await
        .expect("unavailable response");
    let status = response.status().as_u16();
    let (decision, err) = map_external_error("wiremock", Some(status), "Service Unavailable", None);
    assert_eq!(decision, RetryDecision::Backoff);
    assert!(
        matches!(&err, FcpError::External { retryable, .. } if *retryable),
        "expected external error, got {err:?}"
    );
    let delay = policy.next_delay(0, decision, None).expect("delay");
    assert_eq!(delay, Duration::from_secs(1));
}

fn retry_after_from_response(response: &reqwest::Response) -> Option<Duration> {
    response
        .headers()
        .get("retry-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
}
