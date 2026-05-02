# Connector Test Coverage Gap

Updated for `flywheel_connectors-l3daw.4` with:

```bash
scripts/ci/test_coverage_scan.sh
```

## Current Inventory

- Connector manifests: 150
- Connector-local `tests/` directories before `l3daw.4`: 112
- Connectors without `tests/` directories before `l3daw.4`: 38
- Connector-local `tests/` directories after `l3daw.4`: 116
- Connectors without `tests/` directories after `l3daw.4`: 34
- Connectors with new ConnectorSuite-shaped mock-server tests in `l3daw.4`: `deepgram`, `elevenlabs`, `perplexity-search`, `wolfram`
- Scanner deterministic-contract connectors after `l3daw.4`: 118

The scan also reports more than ten connectors still missing acceptance-suite coverage, so the remaining breadth must be handled in follow-up beads rather than hidden inside one oversized patch.

## Closed In l3daw.4

| Connector | Classification | Coverage added |
| --- | --- | --- |
| `deepgram` | active, live-read-only, request-response HTTP | ConnectorSuite configure + handshake + `deepgram.listen.transcribe` happy path against `wiremock`. |
| `elevenlabs` | active, live-read-only, request-response HTTP | ConnectorSuite configure + handshake + `elevenlabs.voices.list` happy path against `wiremock`. |
| `perplexity-search` | active, local-sufficient, request-response HTTP | ConnectorSuite configure + handshake + signed `perplexity-search.query` happy path against `wiremock`. |
| `wolfram` | active, live-read-only, request-response HTTP | ConnectorSuite configure + handshake + `wolfram.short_answer` happy path against `wiremock`. |

## Closed In l3daw.3

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
| `dockerhub` | sandbox_required | active API | Add mock-server deterministic contract tests plus sandbox/live gate. |
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
| `zalo` | live_write_required | active API | Add mock-server deterministic contract tests plus live write gate. |
| `zalouser` | live_write_required | quarantined manifest | Keep quarantined until helper boundary proof exists. |

## Gate Status

The repository already has `scripts/ci/test_coverage_scan.sh` for machine-readable connector coverage classification. The current scan reports 118 connector deterministic contracts but still fails on pre-existing acceptance-suite and live-suite breadth gaps, so it should not be wired as a hard all-connector gate until the remaining queue above is split and burned down.
