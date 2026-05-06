# Telnyx Connector

`fcp-telnyx` is the standalone Flywheel Connector Protocol voice-call provider for Telnyx Call Control. It intentionally remains separate from Twilio and Plivo while sharing provider-neutral call-auth, replay, session, and webhook verification primitives through `fcp-voice-call`.

## Operations

- `telnyx.call.initiate`
- `telnyx.call.continue`
- `telnyx.call.speak`
- `telnyx.call.end`
- `telnyx.call.status`
- `telnyx.call.transfer`
- `telnyx.call.gather`
- `telnyx.webhook.validate_signature`
- `telnyx.webhook.evaluate_inbound_policy`
- `telnyx.webhook.parse_event`
- `telnyx.webhook.ingest_request`

## Security Posture

- Direct `api_key` mode is constrained to `https://api.telnyx.com/v2`, with localhost-only overrides for deterministic tests.
- Secretless `credential_id` mode sends only `X-FCP-Credential-ID` for egress proxy injection.
- Telnyx webhook signatures are verified with `Telnyx-Signature-Ed25519` and `Telnyx-Timestamp` through `fcp-voice-call`.
- Replay cache insertion occurs only after a valid signature.
- Callback/session binding uses an FCP-issued `CallAuthToken` embedded in Telnyx `client_state`.
- E2E logs hash or mask call IDs and phone numbers and must never include full E.164 numbers, API keys, auth tokens, raw audio, transcripts, or full webhook bodies.

## Verification

Default verification requires no live Telnyx credentials:

```bash
bash scripts/e2e/telnyx_connector_verification.sh
```

The script runs the no-live-credential loopback connector-boundary harness and prints the JSONL artifact path through the Rust test output.
