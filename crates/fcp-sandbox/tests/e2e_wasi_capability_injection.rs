use fcp_manifest::NetworkConstraints;
use fcp_sandbox::{
    CredentialInjector, EgressError, EgressHttpRequest, HttpHeader, WasiConfig, WasiRuntime,
};
use tracing::{Level, span};

const fn minimal_command_component() -> &'static [u8] {
    br#"
    (component
        (core module $m
            (func (export "run"))
        )
        (core instance $i (instantiate $m))
        (func (export "run") (canon lift (core func $i "run")))
    )
    "#
}

fn mediated_constraints() -> NetworkConstraints {
    NetworkConstraints {
        host_allow: vec!["api.example.com".to_string()],
        port_allow: vec![443],
        ip_allow: vec![],
        cidr_deny: vec!["127.0.0.0/8".to_string(), "100.64.0.0/10".to_string()],
        deny_localhost: true,
        deny_private_ranges: true,
        deny_tailnet_ranges: true,
        require_sni: true,
        spki_pins: vec![],
        deny_ip_literals: true,
        require_host_canonicalization: true,
        dns_max_ips: 16,
        max_redirects: 3,
        connect_timeout_ms: 1_000,
        total_timeout_ms: 5_000,
        max_response_bytes: 1024 * 1024,
    }
}

#[derive(Debug)]
struct StaticCredentialInjector;

impl CredentialInjector for StaticCredentialInjector {
    fn is_authorized(
        &self,
        credential_id: &str,
        operation_id: &str,
        credential_allow: &[String],
    ) -> Result<bool, EgressError> {
        Ok(credential_id == "cred:weather"
            && operation_id == "sandbox.invoke.weather"
            && credential_allow
                .iter()
                .any(|allowed| allowed == credential_id))
    }

    fn is_host_allowed(&self, credential_id: &str, host: &str) -> Result<bool, EgressError> {
        Ok(credential_id == "cred:weather" && host == "api.example.com")
    }

    fn inject_http(
        &self,
        credential_id: &str,
        headers: &mut Vec<HttpHeader>,
    ) -> Result<(), EgressError> {
        headers.push(HttpHeader {
            name: "Authorization".to_string(),
            value: format!("Bearer e2e-token-for-{credential_id}"),
        });
        Ok(())
    }

    fn get_tcp_auth(&self, _credential_id: &str) -> Result<Option<Vec<u8>>, EgressError> {
        Ok(None)
    }
}

#[fcp_async_core::runtime::test]
async fn e2e_wasi_module_loads_injects_capability_and_executes() {
    let mut phases = Vec::new();

    let runtime = {
        let span = span!(
            Level::INFO,
            "e2e_wasi_phase",
            crate_name = "fcp-sandbox",
            phase = "runtime"
        );
        let _entered = span.enter();
        phases.push("runtime");
        WasiRuntime::new(WasiConfig {
            max_fuel: 20_000,
            ..WasiConfig::default().with_network_constraints(mediated_constraints())
        })
        .expect("real wasmtime runtime")
    };

    let component = {
        let span = span!(
            Level::INFO,
            "e2e_wasi_phase",
            crate_name = "fcp-sandbox",
            phase = "load_component"
        );
        let _entered = span.enter();
        phases.push("load_component");
        runtime
            .load_component(minimal_command_component())
            .expect("component text compiles through wasmtime")
    };

    let store = {
        let span = span!(
            Level::INFO,
            "e2e_wasi_phase",
            crate_name = "fcp-sandbox",
            phase = "create_store"
        );
        let _entered = span.enter();
        phases.push("create_store");
        runtime.create_store().expect("WASI store")
    };

    {
        let span = span!(
            Level::INFO,
            "e2e_wasi_phase",
            crate_name = "fcp-sandbox",
            phase = "inject_capability"
        );
        let _entered = span.enter();
        phases.push("inject_capability");
        let injector = StaticCredentialInjector;
        let mut request = EgressHttpRequest {
            url: "https://api.example.com/v1/weather".to_string(),
            method: "GET".to_string(),
            headers: vec![],
            body: None,
            credential_id: Some("cred:weather".to_string()),
        };
        let decision = store
            .data()
            .authorize_http_request(
                &mut request,
                &injector,
                "sandbox.invoke.weather",
                &["cred:weather".to_string()],
            )
            .expect("mediated egress authorizes and injects");
        assert!(decision.allowed);
        assert_eq!(decision.expected_sni.as_deref(), Some("api.example.com"));
        assert!(decision.credential_injected);
        assert!(request.headers.iter().any(|header| {
            header.name == "Authorization" && header.value == "Bearer e2e-token-for-cred:weather"
        }));
    }

    {
        let span = span!(
            Level::INFO,
            "e2e_wasi_phase",
            crate_name = "fcp-sandbox",
            phase = "execute"
        );
        let _entered = span.enter();
        phases.push("execute");
        let result = runtime
            .invoke(&component, "run", &["--e2e".to_string()])
            .await
            .expect("component run");
        assert_eq!(result.exit_code, 0);
        assert!(result.fuel_consumed.is_some());
    }

    assert_eq!(
        phases,
        [
            "runtime",
            "load_component",
            "create_store",
            "inject_capability",
            "execute"
        ]
    );
}
