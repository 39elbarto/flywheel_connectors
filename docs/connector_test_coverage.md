# Connector Test Coverage Gap

Generated for `flywheel_connectors-l3daw.3` with:

```bash
scripts/ci/test_coverage_scan.sh --only connectors --json-out /tmp/fcp_connector_coverage.json --summary-out /tmp/fcp_connector_coverage.md
```

## Current Inventory

- Connector manifests: 150
- Connector-local `tests/` directories before this slice: 108
- Connectors without `tests/` directories before this slice: 42
- Connectors with new ConnectorSuite-shaped mock-server tests in this slice: `exa`, `mistral`, `openrouter`, `tavily`

The scan also reports more than ten connectors still missing acceptance-suite coverage, so the remaining breadth must be handled in follow-up beads rather than hidden inside one oversized patch.

## Closed In This Slice

| Connector | Classification | Coverage added |
| --- | --- | --- |
| `exa` | active, local-sufficient, request-response HTTP | ConnectorSuite configure + handshake + `exa.search` happy path against `wiremock`, plus expected upstream error path. |
| `tavily` | active, local-sufficient, request-response HTTP | ConnectorSuite configure + handshake + `tavily.search` happy path against `wiremock`, plus expected upstream error path. |
| `openrouter` | active, local-sufficient, request-response HTTP | ConnectorSuite configure + handshake + `openrouter.models.list` happy path against `wiremock`, plus expected rate-limit error path. |
| `mistral` | active, local-sufficient, request-response HTTP | ConnectorSuite configure + handshake + `mistral.models.list` happy path against `wiremock`, plus expected rate-limit error path. |

## Remaining No-Tests Directory Queue

| Connector | Scan tier | Classification | Required next action |
| --- | --- | --- | --- |
| `apple-notes` | device_required | native-local/device | Add explicit native-local manifest status or device-gated suite. |
| `apple-reminders` | device_required | native-local/device | Add explicit native-local manifest status or device-gated suite. |
| `bluebubbles` | device_required | native-local/device | Add explicit native-local manifest status or device-gated suite. |
| `circleci` | sandbox_required | active API | Add mock-server deterministic contract tests plus sandbox/live gate. |
| `confluence` | sandbox_required | active API | Add mock-server deterministic contract tests plus sandbox/live gate. |
| `deepgram` | live_read_only | active API | Add mock-server deterministic contract tests plus live read-only gate. |
| `dockerhub` | sandbox_required | active API | Add mock-server deterministic contract tests plus sandbox/live gate. |
| `elevenlabs` | live_read_only | active API | Add mock-server deterministic contract tests plus live read-only gate. |
| `email-generic` | local_sufficient | active local protocol | Add local protocol fixture tests or classify as requiring live mail fixture. |
| `google-admin-reports` | local_sufficient | active API | Add mock-server deterministic contract tests. |
| `google-chat` | local_sufficient | active API | Add mock-server deterministic contract tests and clean source mock leakage. |
| `google-people` | local_sufficient | active API | Add mock-server deterministic contract tests. |
| `google-workspace-events` | local_sufficient | active API | Add mock-server deterministic contract tests and clean source mock leakage. |
| `huggingface` | local_sufficient | incubating manifest | Keep incubating or graduate with mock + live/read proof. |
| `imessage` | device_required | native-local/device | Add explicit native-local manifest status or device-gated suite. |
| `irc` | live_read_only | active network protocol | Add protocol fixture tests plus live read-only gate. |
| `mastodon` | local_sufficient | active API | Add connector-local mock-server suite or move existing source tests into `tests/`. |
| `matrix` | local_sufficient | active API | Add connector-local mock-server suite or move existing source tests into `tests/`. |
| `mattermost` | local_sufficient | active API | Add connector-local mock-server suite. |
| `netlify` | sandbox_required | active API | Add mock-server deterministic contract tests plus sandbox/live gate. |
| `nextcloud-talk` | local_sufficient | active API | Add mock-server deterministic contract tests and clean source mock leakage. |
| `nostr` | live_write_required | active network protocol | Add protocol fixture tests plus live write gate. |
| `outlook` | unclassified | active API | Classify live tier and add mock-server deterministic contract tests. |
| `paypal` | sandbox_required | active API | Add mock-server deterministic contract tests plus sandbox/live gate. |
| `perplexity-search` | local_sufficient | active API with source-adjacent mocks | Move existing mock coverage into connector-local `tests/` and add ConnectorSuite wrapper. |
| `redis` | local_sufficient | active local protocol | Raise pure-unit floor and add local fixture suite. |
| `shopify` | sandbox_required | active API | Add mock-server deterministic contract tests plus sandbox/live gate. |
| `signal` | device_required | native-local/device | Add explicit native-local manifest status or device-gated suite. |
| `sonos` | device_required | native-local/device | Add explicit native-local manifest status or device-gated suite. |
| `teams` | sandbox_required | active API | Add mock-server deterministic contract tests plus sandbox/live gate. |
| `tlon` | live_write_required | incubating manifest | Keep incubating until a real live write proof exists. |
| `twitch` | unclassified | active API | Classify live tier and add mock-server deterministic contract tests. |
| `vercel` | sandbox_required | active API | Add mock-server deterministic contract tests plus sandbox/live gate. |
| `wecom` | live_write_required | active API | Add mock-server deterministic contract tests plus live write gate. |
| `whisper` | device_required | native-local/device | Add explicit native-local manifest status or device-gated suite and pure-unit signal. |
| `wolfram` | live_read_only | active API | Add mock-server deterministic contract tests plus live read-only gate. |
| `zalo` | live_write_required | active API | Add mock-server deterministic contract tests plus live write gate. |
| `zalouser` | live_write_required | quarantined manifest | Keep quarantined until helper boundary proof exists. |

## Gate Status

The repository already has `scripts/ci/test_coverage_scan.sh` for machine-readable connector coverage classification. It currently fails on pre-existing breadth gaps, so it should not be wired as a hard all-connector gate until the remaining queue above is split and burned down.
