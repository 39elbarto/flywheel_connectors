use fcp_groq::GroqConnector;
use fcp_manifest::{ConnectorManifest, ManifestApprovalMode};
use fcp_prelude::{ApprovalMode, FcpConnector};

const OPERATION_ORDER: [&str; 6] = [
    "groq.chat.completions",
    "groq.chat.completions_stream",
    "groq.models.list",
    "groq.health",
    "groq.embeddings.create",
    "groq.completions.legacy",
];

fn strict_manifest() -> ConnectorManifest {
    ConnectorManifest::parse_str(include_str!("../manifest.toml"))
        .expect("Groq manifest should parse with strict schema")
}

fn approval_mode_from_manifest(mode: ManifestApprovalMode) -> Option<ApprovalMode> {
    match mode {
        ManifestApprovalMode::None => None,
        other => Some(ApprovalMode::from(other)),
    }
}

#[test]
fn manifest_declares_required_operations_and_network_policy() {
    let manifest: toml::Value =
        toml::from_str(include_str!("../manifest.toml")).expect("manifest should parse");
    let operations = manifest
        .get("provides")
        .and_then(|value| value.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("operations table should exist");

    for operation in [
        "groq.chat.completions",
        "groq.chat.completions_stream",
        "groq.models.list",
        "groq.health",
        "groq.embeddings.create",
        "groq.completions.legacy",
    ] {
        let op = operations
            .get(operation)
            .expect("operation should be declared");
        let constraints = op
            .get("network_constraints")
            .and_then(toml::Value::as_table)
            .expect("network constraints should exist");
        assert_eq!(
            constraints
                .get("require_sni")
                .and_then(toml::Value::as_bool),
            Some(true)
        );
        assert_eq!(
            constraints
                .get("deny_private_ranges")
                .and_then(toml::Value::as_bool),
            Some(true)
        );
    }

    assert_eq!(
        operations
            .get("groq.embeddings.create")
            .and_then(|op| op.get("description"))
            .and_then(toml::Value::as_str),
        Some(
            "Declared for introspection honesty. Groq does not currently expose embeddings through the first-party Groq API."
        )
    );
    assert_eq!(
        operations
            .get("groq.completions.legacy")
            .and_then(|op| op.get("description"))
            .and_then(toml::Value::as_str),
        Some("Minimal deprecated legacy /completions support for older OpenAI-compatible clients.")
    );
}

#[test]
fn introspection_matches_manifest_operation_surface() {
    let manifest = strict_manifest();
    let connector = GroqConnector::new();
    let introspection = connector.introspect();
    let ids = introspection
        .operations
        .iter()
        .map(|operation| operation.id.as_str())
        .collect::<Vec<_>>();

    assert_eq!(ids, OPERATION_ORDER.to_vec());
    assert_eq!(manifest.provides.operations.len(), OPERATION_ORDER.len());

    for operation in introspection.operations {
        let operation_id = operation.id.as_str();
        let manifest_operation = manifest
            .provides
            .operations
            .get(operation_id)
            .unwrap_or_else(|| panic!("manifest should declare {operation_id}"));

        assert_eq!(operation.summary, manifest_operation.description);
        assert_eq!(
            operation.description.as_ref(),
            Some(&manifest_operation.description)
        );
        assert_eq!(operation.input_schema, manifest_operation.input_schema);
        assert_eq!(operation.output_schema, manifest_operation.output_schema);
        assert_eq!(operation.capability, manifest_operation.capability);
        assert_eq!(operation.risk_level, manifest_operation.risk_level);
        assert_eq!(operation.safety_tier, manifest_operation.safety_tier);
        assert_eq!(operation.idempotency, manifest_operation.idempotency);
        assert_eq!(
            operation.requires_approval,
            approval_mode_from_manifest(manifest_operation.requires_approval)
        );
        assert!(
            manifest_operation.network_constraints.is_some(),
            "{operation_id} should declare manifest network constraints"
        );
        assert_eq!(
            operation.ai_hints.when_to_use,
            manifest_operation.ai_hints.when_to_use
        );
        assert_eq!(
            operation.ai_hints.common_mistakes,
            manifest_operation.ai_hints.common_mistakes
        );
        assert_eq!(
            operation.ai_hints.examples,
            manifest_operation.ai_hints.examples
        );
        assert_eq!(
            operation.ai_hints.related,
            manifest_operation.ai_hints.related
        );
    }
}
