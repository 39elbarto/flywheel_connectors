use fcp_irc::IrcConnector;
use fcp_sdk::prelude::{FcpConnector, SelfCheckStatus};
use serde_json::{Map, Value, json};

const LIVE_GATE_ENV: &str = "FCP_LIVE_READ";
const SERVER_ENV: &str = "IRC_LIVE_SERVER";
const PORT_ENV: &str = "IRC_LIVE_PORT";
const TLS_ENV: &str = "IRC_LIVE_TLS";
const NICK_ENV: &str = "IRC_LIVE_NICK";
const OPERATION: &str = "irc.health";

fn live_gate_enabled() -> bool {
    std::env::var(LIVE_GATE_ENV)
        .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

fn env_value(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn env_bool(name: &str, default: bool) -> bool {
    env_value(name).map_or(default, |value| {
        value == "1" || value.eq_ignore_ascii_case("true")
    })
}

fn emit_live_jsonl(status: &str, reason: &str, connector_status: &str) {
    println!(
        "IRC_LIVE_JSONL {}",
        json!({
            "event": "irc_live_read_smoke",
            "fixture_mode": "live",
            "suite_class": "live_read_only",
            "gate_env_var": LIVE_GATE_ENV,
            "required_env": SERVER_ENV,
            "optional_env": [PORT_ENV, TLS_ENV, NICK_ENV],
            "operation": OPERATION,
            "status": status,
            "provider": "IRC server",
            "resource_class": "bounded_registration_health_probe",
            "connector_status": connector_status,
            "call_ceiling": 1,
            "rate_limit_guidance": "Performs one connect/register/QUIT self-check against the configured IRC server.",
            "mutation_expected": false,
            "transient_session_expected": true,
            "cleanup_result": "quit_sent_by_self_check",
            "skip_reason": if status == "skipped" { Some(reason) } else { None },
            "fcp_error_mapping": if status == "failed" { Some(reason) } else { None },
        })
    );
}

#[fcp_async_core::runtime::test]
async fn irc_live_read_health_or_structured_skip_jsonl() {
    if !live_gate_enabled() {
        emit_live_jsonl(
            "skipped",
            &format!("{LIVE_GATE_ENV} is not set to 1"),
            "skipped",
        );
        return;
    }

    let Some(server) = env_value(SERVER_ENV) else {
        emit_live_jsonl("skipped", &format!("{SERVER_ENV} is not set"), "skipped");
        return;
    };
    let port = match env_value(PORT_ENV) {
        Some(value) => match value.parse::<u16>() {
            Ok(port) => Some(port),
            Err(error) => {
                emit_live_jsonl(
                    "skipped",
                    &format!("{PORT_ENV} must be a u16 port: {error}"),
                    "skipped",
                );
                return;
            }
        },
        None => None,
    };

    let mut config = Map::new();
    config.insert("server".to_owned(), json!(server));
    config.insert(
        "nick".to_owned(),
        json!(env_value(NICK_ENV).unwrap_or_else(|| format!("fcplive{}", std::process::id()))),
    );
    config.insert("username".to_owned(), json!("flywheel"));
    config.insert(
        "realname".to_owned(),
        json!("Flywheel Connector Live Read Smoke"),
    );
    config.insert("tls".to_owned(), json!(env_bool(TLS_ENV, true)));
    config.insert("request_timeout_ms".to_owned(), json!(10_000));
    if let Some(port) = port {
        config.insert("port".to_owned(), json!(port));
    }

    let mut connector = IrcConnector::new();
    connector
        .configure(Value::Object(config))
        .await
        .expect("configure IRC live endpoint");

    match connector.self_check().await {
        Ok(report) => {
            let connector_status = format!("{:?}", report.status);
            assert_eq!(
                report.status,
                SelfCheckStatus::Ok,
                "IRC live health self-check should pass"
            );
            emit_live_jsonl("passed", "", &connector_status);
        }
        Err(error) => {
            emit_live_jsonl("failed", &error.to_string(), "error");
            panic!("IRC live read smoke failed: {error}");
        }
    }
}
