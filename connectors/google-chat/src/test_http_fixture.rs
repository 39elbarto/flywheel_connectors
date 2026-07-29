//! Test-only HTTP fixture aliases kept outside source-adjacent test files.

pub mod matchers {
    pub use wiremock::matchers::{
        body_partial_json, body_string_contains, header, header_regex, method, path_regex,
        query_param,
    };
}

pub use wiremock::{Mock, MockServer as HttpServer, ResponseTemplate};
