# Azure Speech Connector

This connector implements the core Azure Speech REST surface for FCP:

- regional token exchange through `issueToken`
- Microsoft Entra access-token handoff for documented keyless REST paths
- `voices/list` discovery
- REST text-to-speech synthesis through `/cognitiveservices/v1`
- Speech-to-text fast and batch transcription through `2025-10-15`

Realtime WebSocket sessions, custom speech project/model lifecycle, and connector-local IMDS/MSAL token acquisition are intentionally separate follow-up surfaces.

## Enterprise Auth Status

`flywheel_connectors-4kw5f.2.9.6.1.4` supports three auth modes without writing secrets to disk:

- `subscription_key` / `api_key`: the connector preserves the existing key path. TTS and voices exchange the key for an issued Speech bearer token; 2025-10-15 STT operations send `Ocp-Apim-Subscription-Key` because the REST reference declares that security scheme.
- `entra_access_token`: the host supplies a current Microsoft Entra access token. When `entra_resource_id` is present, the connector constructs the documented `aad#<resource-id>#<token>` bearer payload and returns only the resource-id hash. When `entra_token_format = "bearer_token"`, the connector sends the raw bearer token for current keyless speech endpoints that document standard Entra bearer auth.
- `credential_id`: the connector emits `X-FCP-Credential-ID` for host/egress credential injection. Direct live self-check remains degraded because Microsoft endpoints require the host to materialize a concrete bearer token before egress.

The connector validates Azure Cognitive Services resource IDs, tracks optional `entra_token_expires_in_seconds`, refuses expired Entra tokens with refresh guidance, and redacts access tokens, subscription keys, tenant/resource identifiers, and provider SAS URLs from connector outputs.

## Speech-to-text REST Status

`flywheel_connectors-4kw5f.2.9.6.1.3` covers the current `2025-10-15` REST paths that are explicit in Microsoft Learn: fast transcription via `/speechtotext/transcriptions:transcribe` and batch transcription submit/status/files via `/speechtotext/transcriptions:submit` plus the transcription resource and files links returned by that API. Batch input accepts storage URLs or a Blob container URL; runtime output redacts provider URLs and SAS-bearing file links into hashes/descriptors.

Custom speech projects, dataset/model training, deployment endpoints, and webhook management are not part of this connector slice.

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
