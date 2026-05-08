# Azure Speech Connector

This connector implements the core Azure Speech REST surface for FCP:

- regional token exchange through `issueToken`
- `voices/list` discovery
- REST text-to-speech synthesis through `/cognitiveservices/v1`
- Speech-to-text fast transcription through `2025-10-15`

Realtime WebSocket sessions, batch transcription, and Microsoft Entra managed identity are intentionally separate follow-up surfaces.
