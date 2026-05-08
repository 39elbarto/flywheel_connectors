# Azure Speech Connector

This connector implements the core Azure Speech REST surface for FCP:

- regional token exchange through `issueToken`
- `voices/list` discovery
- REST text-to-speech synthesis through `/cognitiveservices/v1`
- Speech-to-text fast and batch transcription through `2025-10-15`

Realtime WebSocket sessions, custom speech project/model lifecycle, and Microsoft Entra managed identity are intentionally separate follow-up surfaces.

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
