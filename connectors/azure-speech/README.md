# Azure Speech Connector

This connector implements the core Azure Speech REST surface for FCP:

- regional token exchange through `issueToken`
- Microsoft Entra access-token handoff for documented keyless REST paths
- `voices/list` discovery
- REST text-to-speech synthesis through `/cognitiveservices/v1`
- Speech-to-text fast and batch transcription through `2025-10-15`

Realtime WebSocket sessions, custom speech project/model lifecycle, and connector-local IMDS/MSAL token acquisition are intentionally separate follow-up surfaces: `flywheel_connectors-4kw5f.2.9.6.1.2`, `flywheel_connectors-4kw5f.2.9.6.2`, and `flywheel_connectors-4kw5f.2.9.6.3`.

## Enterprise Auth Status

`flywheel_connectors-4kw5f.2.9.6.1.4` supports three auth modes without writing secrets to disk:

- `subscription_key` / `api_key`: the connector preserves the existing key path. TTS and voices exchange the key for an issued Speech bearer token; 2025-10-15 STT operations send `Ocp-Apim-Subscription-Key` because the REST reference declares that security scheme.
- `entra_access_token`: the host supplies a current Microsoft Entra access token. When `entra_resource_id` is present, the connector constructs the documented `aad#<resource-id>#<token>` bearer payload and returns only the resource-id hash. When `entra_token_format = "bearer_token"`, the connector sends the raw bearer token for current keyless speech endpoints that document standard Entra bearer auth.
- `credential_id`: the connector emits `X-FCP-Credential-ID` for host/egress credential injection. Direct live self-check remains degraded because Microsoft endpoints require the host to materialize a concrete bearer token before egress.

The connector validates Azure Cognitive Services resource IDs, tracks optional `entra_token_expires_in_seconds`, refuses expired Entra tokens with refresh guidance, and redacts access tokens, subscription keys, tenant/resource identifiers, and provider SAS URLs from connector outputs.

All invoke paths require a bound FCP capability token after handshake. The connector verifies the token zone, target instance, operation, capability, and resource constraints before any provider request is built, so a wrong-zone or wrong-instance grant is denied without contacting Azure.

## Speech-to-text REST Status

`flywheel_connectors-4kw5f.2.9.6.1.3` covers the current `2025-10-15` REST paths that are explicit in Microsoft Learn: fast transcription via `/speechtotext/transcriptions:transcribe` and batch transcription submit/status/files via `/speechtotext/transcriptions:submit` plus the transcription resource and files links returned by that API. Batch input accepts storage URLs or a Blob container URL; runtime output redacts provider URLs and SAS-bearing file links into hashes/descriptors.

Custom speech projects, dataset/model training, deployment endpoints, and webhook management are not part of this connector slice; they are tracked in `flywheel_connectors-4kw5f.2.9.6.2`.

## Realtime WebSocket Status

`flywheel_connectors-4kw5f.2.9.6.1.2` rechecked current Microsoft Learn docs on 2026-05-08. Azure Speech TTS text streaming is documented through Speech SDK `TextStream` on the WebSocket v2 endpoint, and realtime STT is documented through Speech SDK `SpeechRecognizer`/`AudioConfig` stream APIs. Microsoft does not publish the direct WebSocket frame protocol needed for a standalone Rust connector.

This connector therefore keeps realtime STT/TTS WebSocket operations blocked instead of guessing the live wire format. The implementation gate is explicit in runtime introspection under `streaming_blocker` and `deferred_operations`.

Current docs:

- <https://learn.microsoft.com/en-us/azure/ai-services/speech-service/how-to-lower-speech-synthesis-latency#how-to-use-text-streaming>
- <https://learn.microsoft.com/en-us/azure/ai-services/speech-service/how-to-recognize-speech>
- <https://learn.microsoft.com/en-us/azure/ai-services/speech-service/how-to-control-connections>
- <https://learn.microsoft.com/en-us/azure/ai-services/speech-service/rest-text-to-speech#authentication>
- <https://learn.microsoft.com/en-us/azure/ai-services/speech-service/how-to-configure-azure-ad-auth>
- <https://learn.microsoft.com/en-us/azure/ai-services/speech-service/llm-speech>

## Verification

The closeout proof lane is `scripts/e2e/azure_speech_connector_verification.sh`. It runs the no-live-credential loopback matrix through the production connector boundary and emits redacted JSONL records for token issue, voices.list, TTS synth, STT fast transcription, batch submit/get/files, provider error redaction, rate-limit retry, timeout, malformed input, unsupported format, oversized audio, capability-token zone and instance denial, harness cancellation, streaming blocker disposition, shutdown cleanup, and optional live-smoke skip/pass state.

The JSONL contract records command line, git revision, connector id, operation id, capability, zone, instance id, fixture/live mode, region and endpoint class, auth mode, voice/language/model id, content type, audio byte counts, transcript length only, stream chunk count, HTTP status, retry/backoff decision, FCP error mapping, latency, result, audit receipt id, cleanup result, and skip reason. It deliberately rejects keys, bearer tokens, tenant/resource IDs, SAS URLs, SSML/text content, transcripts, raw audio bytes, provider bodies, local absolute paths, and PII.
