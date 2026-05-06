# fcp-plivo

`fcp-plivo` is the standalone Flywheel Connector Protocol voice-call provider
for Plivo Voice. It intentionally remains separate from Twilio and Telnyx while
sharing provider-neutral call-auth, replay, session, redaction, and webhook
verification primitives through `fcp-voice-call`.

## Configuration

Direct API mode accepts `auth_id` and `auth_token` in memory only. Secretless API
mode accepts `auth_id`, `credential_id`, and `webhook_auth_token`; the raw API
credential is then injected by the FCP egress layer while the webhook HMAC secret
is retained in memory for signature validation.

Direct API mode is constrained to `https://api.plivo.com/v1/Account/<auth_id>`
except for localhost loopback tests. Webhook validation is V3-first with V2
fallback and accepts Plivo's comma-separated multi-signature header form.

## Operations

- `plivo.call.initiate`
- `plivo.call.continue`
- `plivo.call.speak`
- `plivo.call.end`
- `plivo.call.status`
- `plivo.call.transfer`
- `plivo.call.gather`
- `plivo.webhook.validate_signature`
- `plivo.webhook.evaluate_inbound_policy`
- `plivo.webhook.parse_event`
- `plivo.webhook.ingest_request`

`plivo.call.gather` returns Plivo GetDigits XML instead of pretending that
Plivo has a Telnyx-style REST gather action.

## Verification

Default tests use loopback fixtures only and require no live Plivo credentials.
Run:

```bash
bash scripts/e2e/plivo_connector_verification.sh
```

Set `PLIVO_LIVE_E2E=1` to exercise the live-credential preflight. If
`PLIVO_AUTH_ID` or `PLIVO_AUTH_TOKEN` is absent, the script emits a structured
JSONL skip record instead of making network calls.
