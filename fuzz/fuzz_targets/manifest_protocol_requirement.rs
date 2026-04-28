#![no_main]

use fcp_manifest::{ManifestSchemaVersion, ProtocolRequirement, ProtocolVersion};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 512;

fn assert_schema_version_roundtrip(input: &str) {
    if let Ok(version) = ManifestSchemaVersion::try_from(input.to_owned()) {
        let rendered = version.to_string();
        let reparsed = ManifestSchemaVersion::try_from(rendered.clone())
            .expect("displayed manifest schema version should parse");
        assert_eq!(reparsed, version);

        let json = serde_json::to_string(&version).expect("schema version should serialize");
        assert_eq!(
            json,
            serde_json::to_string(&rendered).expect("string serializes")
        );
        let decoded: ManifestSchemaVersion =
            serde_json::from_str(&json).expect("serialized schema version should decode");
        assert_eq!(decoded, version);
    }
}

fn assert_protocol_version_roundtrip(input: &str) {
    if let Ok(version) = ProtocolVersion::try_from(input.to_owned()) {
        let rendered = version.to_string();
        let reparsed =
            ProtocolVersion::try_from(rendered).expect("displayed protocol version should parse");
        assert_eq!(reparsed, version);
    }
}

fn assert_protocol_requirement_roundtrip(input: &str) {
    if let Ok(requirement) = ProtocolRequirement::try_from(input.to_owned()) {
        let rendered = requirement.to_string();
        let reparsed = ProtocolRequirement::try_from(rendered.clone())
            .expect("displayed protocol requirement should parse");
        assert_eq!(reparsed, requirement);

        let json = serde_json::to_string(&requirement).expect("requirement should serialize");
        assert_eq!(
            json,
            serde_json::to_string(&rendered).expect("string serializes")
        );
        let decoded: ProtocolRequirement =
            serde_json::from_str(&json).expect("serialized requirement should decode");
        assert_eq!(decoded, requirement);
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    if let Ok(input) = std::str::from_utf8(data) {
        assert_schema_version_roundtrip(input);
        assert_protocol_version_roundtrip(input);
        assert_protocol_requirement_roundtrip(input);
    }

    if let Ok(requirement) = serde_json::from_slice::<ProtocolRequirement>(data) {
        assert_protocol_requirement_roundtrip(&requirement.to_string());
    }

    if let Ok(version) = serde_json::from_slice::<ManifestSchemaVersion>(data) {
        assert_schema_version_roundtrip(&version.to_string());
    }
});
