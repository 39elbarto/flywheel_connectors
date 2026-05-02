use fcp_telemetry::trace_capture::{
    CapturedTrace, MeshTraceRedactionLevel, PolicyDecision, RoutingDecision, SessionEvent,
    TraceCapture, TraceCaptureConfig, TraceEvent, TraceExportFormat,
};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{Level, span};

fn unique_trace_path(level: MeshTraceRedactionLevel, extension: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    path.push(format!(
        "fcp-telemetry-e2e-{level:?}-{}-{nanos}.{extension}",
        std::process::id()
    ));
    path
}

fn capture_for(level: MeshTraceRedactionLevel) -> TraceCapture {
    let config = TraceCaptureConfig::new()
        .enabled()
        .with_redaction_level(level);
    let mut capture =
        TraceCapture::new("capture-node-secret-e2e", config).with_node("node-secret-e2e");
    capture
        .record(TraceEvent::Routing(RoutingDecision {
            timestamp: 1,
            trace_id: "trace-secret-e2e".to_string(),
            source_node: "source-node-secret-e2e".to_string(),
            target_node: Some("target-node-secret-e2e".to_string()),
            object_id: "object-secret-e2e".to_string(),
            path_type: "direct".to_string(),
            decision: "routed".to_string(),
            reason: None,
        }))
        .expect("routing event");
    capture
        .record(TraceEvent::Policy(PolicyDecision {
            timestamp: 2,
            trace_id: "trace-secret-e2e".to_string(),
            zone_id: "z:secret-e2e".to_string(),
            operation: "invoke".to_string(),
            connector_id: "connector-secret-e2e".to_string(),
            decision: "allow".to_string(),
            reason_code: "OK".to_string(),
            evidence: vec![
                "owner-public-key-secret-e2e".to_string(),
                "signed-head-bytes-secret-e2e".to_string(),
            ],
        }))
        .expect("policy event");
    capture
        .record(TraceEvent::Session(SessionEvent {
            timestamp: 3,
            trace_id: "trace-secret-e2e".to_string(),
            session_id: "session-secret-e2e".to_string(),
            kind: "established".to_string(),
            peer_node: "peer-node-secret-e2e".to_string(),
            suite: Some("suite-e2e".to_string()),
            failure_reason: None,
        }))
        .expect("session event");
    capture.finish();
    capture
}

fn assert_level(level: MeshTraceRedactionLevel, json: &str) {
    match level {
        MeshTraceRedactionLevel::None => {
            assert!(json.contains("owner-public-key-secret-e2e"));
            assert!(json.contains("signed-head-bytes-secret-e2e"));
            assert!(json.contains("source-node-secret-e2e"));
            assert!(!json.contains("[REDACTED]"));
        }
        MeshTraceRedactionLevel::Identifiers => {
            for leaked in [
                "owner-public-key-secret-e2e",
                "signed-head-bytes-secret-e2e",
                "source-node-secret-e2e",
                "target-node-secret-e2e",
                "peer-node-secret-e2e",
                "session-secret-e2e",
            ] {
                assert!(!json.contains(leaked), "{level:?} leaked {leaked}");
            }
            assert!(json.contains("[REDACTED]"));
            assert!(!json.contains("[REDACTED:"));
        }
        MeshTraceRedactionLevel::Full => {
            for leaked in [
                "owner-public-key-secret-e2e",
                "signed-head-bytes-secret-e2e",
                "source-node-secret-e2e",
                "target-node-secret-e2e",
                "peer-node-secret-e2e",
                "session-secret-e2e",
            ] {
                assert!(!json.contains(leaked), "{level:?} leaked {leaked}");
            }
            assert!(json.contains("[REDACTED:"));
        }
    }
}

#[test]
fn e2e_trace_capture_exports_round_trip_across_redaction_levels() {
    let mut phases = Vec::new();

    for level in [
        MeshTraceRedactionLevel::None,
        MeshTraceRedactionLevel::Identifiers,
        MeshTraceRedactionLevel::Full,
    ] {
        let capture = {
            let span = span!(
                Level::INFO,
                "e2e_telemetry_phase",
                crate_name = "fcp-telemetry",
                phase = "capture",
                redaction_level = ?level
            );
            let _entered = span.enter();
            phases.push(format!("capture:{level:?}"));
            capture_for(level)
        };

        let json = {
            let span = span!(
                Level::INFO,
                "e2e_telemetry_phase",
                crate_name = "fcp-telemetry",
                phase = "export_json",
                redaction_level = ?level
            );
            let _entered = span.enter();
            phases.push(format!("json:{level:?}"));
            let path = unique_trace_path(level, "json");
            capture
                .export_to_path(&path, TraceExportFormat::Json)
                .expect("json export");
            std::fs::read_to_string(&path).expect("json trace")
        };
        assert_level(level, &json);
        let parsed_json = CapturedTrace::from_json(&json).expect("json round trip");
        assert_eq!(parsed_json.events.len(), 3);
        assert_eq!(parsed_json.redacted, level != MeshTraceRedactionLevel::None);

        {
            let span = span!(
                Level::INFO,
                "e2e_telemetry_phase",
                crate_name = "fcp-telemetry",
                phase = "export_cbor",
                redaction_level = ?level
            );
            let _entered = span.enter();
            phases.push(format!("cbor:{level:?}"));
            let path = unique_trace_path(level, "cbor");
            capture
                .export_to_path(&path, TraceExportFormat::Cbor)
                .expect("cbor export");
            let bytes = std::fs::read(&path).expect("cbor trace");
            let parsed_cbor = CapturedTrace::from_cbor(&bytes).expect("cbor round trip");
            assert_eq!(parsed_cbor.events.len(), 3);
            assert_eq!(parsed_cbor.redacted, level != MeshTraceRedactionLevel::None);
        }
    }

    assert_eq!(
        phases,
        [
            "capture:None",
            "json:None",
            "cbor:None",
            "capture:Identifiers",
            "json:Identifiers",
            "cbor:Identifiers",
            "capture:Full",
            "json:Full",
            "cbor:Full"
        ]
    );
}
