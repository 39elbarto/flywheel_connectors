# Inworld Connector

Native FCP connector for the current Inworld character and voice-agent APIs.
The initial implementation focuses on the operational surfaces that Inworld
currently documents for new integrations:

- Realtime WebSocket sessions at `/api/v1/realtime/session`
- TTS bidirectional WebSocket contexts at `/tts/v1/voice:streamBidirectional`
- Router chat completions at `/v1/chat/completions`

Older REST-style `openSession`, `sendText`, `characters.list`, and
`scenes.list` operation names are intentionally absent from the connector
catalog and tests.

## Operations

| Operation | Capability | Provider surface |
| --- | --- | --- |
| `inworld.realtime.text_turn` | `inworld.realtime.invoke` | Realtime WebSocket `session.update`, `conversation.item.create`, `response.create` |
| `inworld.realtime.audio_turn` | `inworld.realtime.invoke` | Realtime WebSocket `input_audio_buffer.*`, `response.create` |
| `inworld.tts.context_roundtrip` | `inworld.tts` | TTS WebSocket `create`, `send_text`, `close_context` |
| `inworld.router.chat_completion` | `inworld.router.chat` | Router REST `POST /v1/chat/completions` |
| `inworld.health` | `inworld.health.read` | Local health/configuration report (no provider egress) |

## Configuration

Exactly one credential mode must be supplied:

- `api_key`: sent as an `Authorization: Basic ...` header
- `bearer_token`: sent as an `Authorization: Bearer ...` header
- `credential_id`: accepted for host-side credential injection, but direct
  connector egress reports that injection is required

Optional URL overrides are accepted for deterministic loopback tests:

- `realtime_ws_url`
- `tts_ws_url`
- `router_base_url`
- `request_timeout_ms`

Production URLs are restricted to `api.inworld.ai` and loopback plaintext
`ws://` / `http://` URLs are only allowed for local fixtures.

## Redaction Contract

Operation outputs are metadata-first. They include hashes, byte counts, event
types, and usage objects where useful, but do not preserve raw prompts, user
text, generated transcripts, synthesized audio, API keys, JWTs, or provider
response bodies. Tests assert this contract for Realtime, Router, and emitted
fixture JSONL.

## Verification

Targeted proof for this connector should run through `rch` once the workspace
manifest includes `connectors/inworld`:

```bash
rch exec -- cargo test -p fcp-inworld -- --nocapture
rch exec -- cargo clippy -p fcp-inworld --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

The integration suite starts real loopback WebSocket servers for Realtime and
TTS, plus a `wiremock` Router endpoint. Live provider verification is skipped
unless the required Inworld credential environment variables are present.
