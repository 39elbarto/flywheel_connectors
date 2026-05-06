//! Plivo connector binary entry point.

use fcp_plivo::PlivoConnector;

const fn ready_message() -> &'static str {
    "fcp-plivo connector ready"
}

fn main() {
    tracing_subscriber::fmt::init();
    let _connector = PlivoConnector::new();
    println!("{}", ready_message());
}

#[cfg(test)]
mod tests {
    use super::ready_message;

    #[test]
    fn binary_ready_message_is_stable() {
        assert_eq!(ready_message(), "fcp-plivo connector ready");
    }
}
