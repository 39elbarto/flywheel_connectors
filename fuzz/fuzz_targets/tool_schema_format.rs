#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::tool_schema::ToolSchemaFormat;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_LEN: usize = 128;

#[derive(Arbitrary, Debug)]
struct Input {
    raw: Vec<u8>,
    variant: u8,
}

fn truncate_at_char_boundary(s: &str) -> &str {
    if s.len() <= MAX_INPUT_LEN {
        return s;
    }

    let mut end = MAX_INPUT_LEN;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn canonical_format(discriminant: u8) -> ToolSchemaFormat {
    match discriminant % 3 {
        0 => ToolSchemaFormat::Mcp,
        1 => ToolSchemaFormat::Claude,
        _ => ToolSchemaFormat::OpenAi,
    }
}

fn assert_canonical_json(format: ToolSchemaFormat, expected: &str) {
    assert_eq!(format.to_string(), expected);

    let json = serde_json::to_string(&format).expect("format must serialize");
    assert_eq!(json, format!("\"{expected}\""));
    assert_eq!(
        serde_json::from_str::<ToolSchemaFormat>(&json).expect("canonical format must deserialize"),
        format
    );
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut unstructured) else {
        return;
    };

    let owned = String::from_utf8_lossy(&input.raw).into_owned();
    let candidate = truncate_at_char_boundary(&owned);
    let quoted = serde_json::to_string(candidate).expect("candidate string must serialize");

    let parsed = serde_json::from_str::<ToolSchemaFormat>(&quoted);
    match candidate {
        "mcp" => assert_eq!(parsed.expect("mcp must deserialize"), ToolSchemaFormat::Mcp),
        "claude" => assert_eq!(
            parsed.expect("claude must deserialize"),
            ToolSchemaFormat::Claude
        ),
        "openai" => assert_eq!(
            parsed.expect("openai must deserialize"),
            ToolSchemaFormat::OpenAi
        ),
        _ => assert!(parsed.is_err(), "non-canonical format string was accepted"),
    }

    match canonical_format(input.variant) {
        ToolSchemaFormat::Mcp => assert_canonical_json(ToolSchemaFormat::Mcp, "mcp"),
        ToolSchemaFormat::Claude => assert_canonical_json(ToolSchemaFormat::Claude, "claude"),
        ToolSchemaFormat::OpenAi => assert_canonical_json(ToolSchemaFormat::OpenAi, "openai"),
    }
});
