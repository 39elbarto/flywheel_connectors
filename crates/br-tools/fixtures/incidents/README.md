# Incident Fixture Corpus

This directory stores redacted, deterministic fixtures for recurring proof and tooling blockers.
Each `*.json` fixture is consumed by `incident-fixture-replay` and must be safe to commit.

Fixture rules:

- Keep excerpts short and representative.
- Use placeholders such as `<repo>`, `<home>`, `<worker>`, `<volume>`, or `[REDACTED_TOKEN]`.
- Never include raw tokens, provider bodies, private local paths, private hostnames, email addresses, or PII.
- Record the safe expected agent action and forbidden actions explicitly.
- Add one fixture per distinct blocker shape instead of mixing unrelated failures.

Replay locally without network or mutation:

```bash
incident-fixture-replay --fixtures crates/br-tools/fixtures/incidents --summary-json /tmp/incident-summary.json --events-jsonl /tmp/incident-events.jsonl --json
```

The replay command itself does not run Cargo, Beads, Agent Mail, or `rch`; it only reads fixture JSON and writes optional report artifacts.
