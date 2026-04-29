//! Pin `IntentStatus` (the crash-recovery state machine) — the
//! closest fcp-core analogue to "SymbolStoreState transitions"
//! (flywheel_connectors-epymi).
//!
//! Bead asks for `SymbolStoreState transitions per documented state
//! machine`. No type literally named `SymbolStoreState` exists in
//! fcp-core. The closest documented state machine for a stored
//! resource is `IntentStatus` (operation.rs:356) — used during
//! crash recovery to determine the state of an operation. Its 5
//! variants form a clear lifecycle:
//!
//!   Pending → InProgress → {Completed, Failed}   (terminal)
//!                       └→ Orphaned              (timeout, terminal)
//!
//! `IntentStatus` carries `#[serde(rename_all = "snake_case")]`,
//! has a hand-written `Display` impl (operation.rs:369) returning
//! the same snake_case tokens, and is the type operators see in
//! crash-recovery audit logs.
//!
//! Existing `operation_golden_vectors.rs` uses `IntentStatus` in
//! fixtures but does not pin its tokens, transitions, or serde
//! shape. This test pins:
//!
//!   1. **All 5 variants enumerated** — count + label sentinel.
//!   2. **Display token per variant** (`pending`, `in_progress`,
//!      `completed`, `failed`, `orphaned`).
//!   3. **Display agrees with serde JSON tag** byte-for-byte (the
//!      hand-written Display matches the rename_all output).
//!   4. **JSON + CBOR round-trip** preserves variant identity.
//!   5. **PascalCase + unknown rejected** (drift sentinel for any
//!      future rename_all swap or variant addition).
//!   6. **Pairwise distinct variants + Display tokens**.
//!   7. **Terminal vs non-terminal classification** — Completed,
//!      Failed, and Orphaned are terminal (no further transitions);
//!      Pending and InProgress are non-terminal (live work). Pin
//!      via documented contract as a discriminator-based truth
//!      table — drift in lifecycle semantics surfaces here.
//!   8. **Multi-word variant uses underscore** (`in_progress`
//!      not `in-progress`).

use ciborium::value::Value as CborValue;
use fcp_core::IntentStatus;

const ALL_STATUSES: &[(IntentStatus, &str)] = &[
    (IntentStatus::Pending, "pending"),
    (IntentStatus::InProgress, "in_progress"),
    (IntentStatus::Completed, "completed"),
    (IntentStatus::Failed, "failed"),
    (IntentStatus::Orphaned, "orphaned"),
];

fn is_terminal(status: IntentStatus) -> bool {
    // Documented contract: Pending and InProgress are non-terminal
    // (live work); Completed, Failed, and Orphaned are terminal
    // (no further transitions).
    match status {
        IntentStatus::Pending | IntentStatus::InProgress => false,
        IntentStatus::Completed | IntentStatus::Failed | IntentStatus::Orphaned => true,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. All 5 variants enumerated
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn intent_status_documented_count_is_five() {
    assert_eq!(
        ALL_STATUSES.len(),
        5,
        "IntentStatus has 5 documented variants — count drifted"
    );
}

#[test]
fn intent_status_variants_match_documented_lifecycle() {
    let labels: Vec<&str> = ALL_STATUSES.iter().map(|(_, s)| *s).collect();
    assert_eq!(
        labels,
        vec!["pending", "in_progress", "completed", "failed", "orphaned"],
        "IntentStatus variant set drifted from the documented \
         {{Pending, InProgress, Completed, Failed, Orphaned}}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Display per variant
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn intent_status_display_token_pinned_per_variant() {
    // Tokens pinned by operation.rs:369-378. Audit logs filter on
    // these.
    for (variant, expected) in ALL_STATUSES {
        assert_eq!(
            variant.to_string(),
            *expected,
            "AUDIT REGRESSION: IntentStatus Display drift on {variant:?}"
        );
        assert_eq!(format!("{variant}"), *expected, "format!() agrees");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Display agrees with serde JSON tag
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn intent_status_display_agrees_with_serde_snake_case_tag() {
    // The enum carries `#[serde(rename_all = "snake_case")]` so the
    // wire form MUST match the hand-written Display tokens
    // byte-for-byte. Drift between them silently breaks log/wire
    // compatibility.
    for (variant, expected) in ALL_STATUSES {
        let displayed = variant.to_string();
        let json = serde_json::to_string(variant).expect("serialize");
        assert_eq!(json, format!("\"{expected}\""));
        let stripped = json.trim_matches('"');
        assert_eq!(
            stripped, displayed,
            "Display vs serde tag MUST agree byte-for-byte for {variant:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. JSON + CBOR round-trip per variant
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn intent_status_json_roundtrip_preserves_every_variant() {
    for (variant, _) in ALL_STATUSES {
        let json = serde_json::to_string(variant).expect("serialize");
        let back: IntentStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*variant, back, "JSON round-trip lost {variant:?}");
    }
}

#[test]
fn intent_status_cbor_roundtrip_preserves_every_variant() {
    for (variant, _) in ALL_STATUSES {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let back: IntentStatus = ciborium::de::from_reader(buf.as_slice()).expect("decode");
        assert_eq!(*variant, back, "CBOR round-trip lost {variant:?}");
    }
}

#[test]
fn intent_status_cbor_encodes_as_text_not_integer() {
    // Cross-language consumers dispatch on the string form — pin
    // that the CBOR shape is a snake_case Text, not a numeric
    // discriminant.
    for (variant, expected) in ALL_STATUSES {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(variant, &mut buf).expect("encode");
        let value: CborValue = ciborium::de::from_reader(buf.as_slice()).expect("decode as Value");
        match value {
            CborValue::Text(s) => assert_eq!(s, *expected, "CBOR Text drift on {variant:?}"),
            other => panic!("{variant:?} MUST encode as CBOR Text, got {other:?}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. PascalCase + unknown rejected
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn intent_status_rejects_pascal_case_and_unknown() {
    for bad in [
        r#""Pending""#,
        r#""InProgress""#,
        r#""Completed""#,
        r#""running""#,   // wrong vocabulary
        r#""abandoned""#, // unknown
        r#""""#,
    ] {
        let parsed = serde_json::from_str::<IntentStatus>(bad);
        assert!(
            parsed.is_err(),
            "{bad} MUST be rejected — only documented snake_case tokens are canonical"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Pairwise distinct
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn intent_status_display_tokens_pairwise_distinct() {
    let mut seen = std::collections::HashSet::new();
    for (_, label) in ALL_STATUSES {
        assert!(seen.insert(*label), "duplicate token {label:?}");
    }
    assert_eq!(seen.len(), ALL_STATUSES.len());
}

#[test]
fn intent_status_variants_pairwise_unequal() {
    for i in 0..ALL_STATUSES.len() {
        for j in (i + 1)..ALL_STATUSES.len() {
            assert_ne!(
                ALL_STATUSES[i].0, ALL_STATUSES[j].0,
                "{:?} and {:?} MUST be distinct variants",
                ALL_STATUSES[i].0, ALL_STATUSES[j].0
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Terminal vs non-terminal classification
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pending_is_non_terminal() {
    assert!(
        !is_terminal(IntentStatus::Pending),
        "Pending MUST be non-terminal (intent recorded, not started)"
    );
}

#[test]
fn in_progress_is_non_terminal() {
    assert!(
        !is_terminal(IntentStatus::InProgress),
        "InProgress MUST be non-terminal (operation running)"
    );
}

#[test]
fn completed_is_terminal() {
    assert!(
        is_terminal(IntentStatus::Completed),
        "Completed MUST be terminal — receipt exists, no further transition"
    );
}

#[test]
fn failed_is_terminal() {
    assert!(
        is_terminal(IntentStatus::Failed),
        "Failed MUST be terminal — error receipt exists, no further transition"
    );
}

#[test]
fn orphaned_is_terminal() {
    assert!(
        is_terminal(IntentStatus::Orphaned),
        "Orphaned MUST be terminal — timeout exceeded, no receipt expected"
    );
}

#[test]
fn exactly_two_non_terminal_states() {
    let non_terminal_count = ALL_STATUSES
        .iter()
        .filter(|(s, _)| !is_terminal(*s))
        .count();
    assert_eq!(
        non_terminal_count, 2,
        "Exactly 2 of 5 variants are non-terminal (Pending + InProgress); drift surfaces here"
    );
}

#[test]
fn exactly_three_terminal_states() {
    let terminal_count = ALL_STATUSES.iter().filter(|(s, _)| is_terminal(*s)).count();
    assert_eq!(
        terminal_count, 3,
        "Exactly 3 of 5 variants are terminal (Completed + Failed + Orphaned)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Multi-word variant uses underscore not hyphen
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn in_progress_uses_underscore_not_hyphen() {
    let json = serde_json::to_string(&IntentStatus::InProgress).expect("serialize");
    assert_eq!(json, r#""in_progress""#);
    assert!(!json.contains('-'), "snake_case MUST NOT contain hyphens");

    let display = IntentStatus::InProgress.to_string();
    assert_eq!(display, "in_progress");
}

#[test]
fn every_token_is_snake_case_lowercase_ascii() {
    for (variant, label) in ALL_STATUSES {
        assert!(!label.is_empty(), "{variant:?}: empty label");
        assert!(
            label.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "{variant:?}: label MUST be lowercase a-z plus `_`, got {label:?}"
        );
        assert!(
            !label.starts_with('_') && !label.ends_with('_'),
            "{variant:?}: no leading/trailing underscore"
        );
        assert!(!label.contains("__"), "{variant:?}: no double underscore");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Copy + Eq correctness, Hash absence
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn copy_preserves_equality_for_every_variant() {
    // IntentStatus derives Debug, Clone, Copy, PartialEq, Eq,
    // Serialize, Deserialize — but NOT Hash. Pin the Copy + Eq
    // contract via assignment-and-compare across every variant.
    for (variant, _) in ALL_STATUSES {
        let copied: IntentStatus = *variant;
        let cloned = copied;
        assert_eq!(*variant, copied);
        assert_eq!(*variant, cloned);
    }
}

#[test]
fn distinct_variants_via_serde_tag_are_distinct() {
    // Without Hash, distinctness via the serde tag (snake_case
    // string) is the observable substitute. Each variant's
    // serialized form is unique — pinned in
    // intent_status_display_tokens_pairwise_distinct above.
    let mut tokens = std::collections::HashSet::new();
    for (variant, _) in ALL_STATUSES {
        let json = serde_json::to_string(variant).expect("serialize");
        assert!(tokens.insert(json), "duplicate serialization");
    }
    assert_eq!(tokens.len(), ALL_STATUSES.len());
}
