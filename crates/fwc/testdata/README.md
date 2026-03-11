This directory holds shared CUAL fixture data for `fwc` tests, integration probes, and shell-level E2E scripts.

Conventions:
- `catalog.json` is the per-file purpose index for JSON, TOML, JSONL, TOON, and future command snapshots.
- JSON files stay strict JSON so they can be deserialized directly in tests.
- TOML and JSONL files are also kept parseable by the real `fwc` parsers.
- `golden/` contains future-facing render snapshots for `fwc access`, `fwc setup`, and `fwc mesh`; those files are syntax-checked and cataloged without claiming the command family is fully implemented yet.
