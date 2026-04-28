use std::collections::HashMap;
use std::str::FromStr;

use fcp_core::{NodeId, TailscaleNodeId};

type TestResult = Result<(), fcp_core::IdValidationError>;

const QUORUM_NODE_IDS: &[&str] = &[
    "",
    "alice",
    "node-1",
    "ts-host.example.com",
    "fcp.host.alpha.beta.gamma",
    "12345678901234567890",
    "n",
];

const TAILSCALE_NODE_IDS: &[&str] = &[
    "node-a",
    "node-1",
    "host.example.com",
    "fcp-host-alpha",
    "ts.fcp.connector.gmail",
];

#[test]
fn quorum_node_id_display_roundtrips_through_constructor() {
    for input in QUORUM_NODE_IDS {
        let original = NodeId::new(input.to_string());
        let display = original.to_string();
        let rebuilt = NodeId::new(display.clone());

        assert_eq!(display, *input);
        assert_eq!(original.as_str(), *input);
        assert_eq!(rebuilt, original);
        assert_eq!(rebuilt.as_str(), display);
    }
}

#[test]
fn quorum_node_id_equality_across_construction_paths() {
    let mut map: HashMap<NodeId, &'static str> = HashMap::new();

    for input in QUORUM_NODE_IDS {
        let owned = NodeId::new(String::from(*input));
        let borrowed = NodeId::new(*input);
        let cloned = owned.clone();
        let display_roundtrip = NodeId::new(owned.to_string());

        assert_eq!(owned, borrowed);
        assert_eq!(owned, cloned);
        assert_eq!(owned, display_roundtrip);

        map.insert(owned, "seen");
        assert_eq!(map.get(&borrowed), Some(&"seen"));
        assert_eq!(map.get(&display_roundtrip), Some(&"seen"));
    }
}

#[test]
fn quorum_node_id_ordering_is_lexical_by_display_text() {
    let mut ids = vec![
        NodeId::new("charlie"),
        NodeId::new("alice"),
        NodeId::new("bob"),
    ];
    ids.sort();

    let sorted: Vec<_> = ids.iter().map(NodeId::as_str).collect();
    assert_eq!(sorted, ["alice", "bob", "charlie"]);
}

#[test]
fn tailscale_node_id_from_str_roundtrips_through_canonical_string() -> TestResult {
    for input in TAILSCALE_NODE_IDS {
        let original = TailscaleNodeId::try_new(*input)?;
        let from_str = TailscaleNodeId::from_str(original.as_str())?;
        let try_from = TailscaleNodeId::try_from(input.to_string())?;
        let cloned = original.clone();

        assert_eq!(from_str, original);
        assert_eq!(try_from, original);
        assert_eq!(cloned, original);

        let owned: String = original.into();
        assert_eq!(owned, *input);
    }

    Ok(())
}

#[test]
fn tailscale_node_id_rejects_noncanonical_from_str_inputs() {
    for input in [
        "",
        "Node-A",
        "NODE",
        "node a",
        "node\ta",
        "node\na",
        "node/x",
        "n\u{00f3}de",
    ] {
        assert!(TailscaleNodeId::try_new(input).is_err());
        assert!(TailscaleNodeId::from_str(input).is_err());
    }
}

#[test]
fn quorum_node_id_and_tailscale_node_id_have_distinct_validation_contracts() {
    let empty_quorum = NodeId::new("");
    let uppercase_quorum = NodeId::new("UPPER");

    assert_eq!(empty_quorum.to_string(), "");
    assert_eq!(uppercase_quorum.to_string(), "UPPER");
    assert!(TailscaleNodeId::try_new("").is_err());
    assert!(TailscaleNodeId::try_new("UPPER").is_err());
}
