//! Test-only HTTP contract support for source-adjacent Jira client tests.

pub use wiremock::ResponseTemplate as HttpResponse;
pub use wiremock::matchers::{method, path};
pub use wiremock::{Mock as HttpExchange, MockServer as HttpServer};
