use std::collections::BTreeMap;

#[test]
fn test_covers_every_agents_md_flow_step() {
    let agents = include_str!("../../../AGENTS.md");
    let docs = include_str!("../../../docs/operator/agent_bootstrap.md");

    let requirements = BTreeMap::from([
        (
            "Register identity",
            "Same Repository Workflow: Register identity",
        ),
        (
            "Reserve files before editing",
            "Same Repository Workflow: Reserve files before editing",
        ),
        (
            "Communicate with threads",
            "Same Repository Workflow: Communicate with threads",
        ),
        ("Quick reads", "Same Repository Workflow: Quick reads"),
        ("Pick ready work", "Typical Agent Flow: Pick ready work"),
        (
            "Reserve edit surface",
            "Typical Agent Flow: Reserve edit surface",
        ),
        ("Announce start", "Typical Agent Flow: Announce start"),
        ("Work and update", "Typical Agent Flow: Work and update"),
        (
            "Complete and release",
            "Typical Agent Flow: Complete and release",
        ),
    ]);

    for (agents_phrase, bootstrap_phrase) in requirements {
        assert!(
            agents.contains(agents_phrase),
            "AGENTS.md no longer contains expected flow item `{agents_phrase}`"
        );
        assert!(
            docs.contains(bootstrap_phrase),
            "agent-bootstrap docs do not map AGENTS.md flow item `{agents_phrase}`"
        );
    }
}
