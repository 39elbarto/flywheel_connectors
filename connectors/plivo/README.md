# fcp-plivo

> **Status**: PROVEN runtime contract documented with remote loopback voice-call verifier proof
> **Verification script**: `scripts/e2e/plivo_connector_verification.sh`
> **Proof**: `target/fcp-plivo/purple-plivo-final-20260606T083600Z/e2e/fcp-plivo-e2e-169354-1780735618735515791/plivo_voice_call_e2e.jsonl`, sha256 `f57f14ae00609ebf4b9da0fa6bff1cc380c8e8ec2cd385cdb130fe1299fb7e43`, 11 redaction-scanned records, rch remote `vmi1293453`

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

Runtime handshake returns a SHA-256 hash of the bundled `manifest.toml`.

## Operator Guidance

- Treat Plivo auth IDs, auth tokens, webhook auth tokens, callback binding
  tokens, full E.164 phone numbers, raw webhook bodies, provider error bodies,
  and callback URLs as sensitive.
- Verification output should use operation IDs, status/error classes,
  retry decisions, signature verdicts, redacted call/session hashes,
  masked caller identity, and JSONL artifact path/hash summaries.

**Common remediation**:

- If configuration fails, provide either direct in-memory `auth_id` and
  `auth_token`, or secretless `auth_id`, `credential_id`, and
  `webhook_auth_token`.
- If provider calls fail in production, confirm the effective base URL is
  `https://api.plivo.com/v1/Account/<auth_id>` and that host egress is limited
  to `api.plivo.com:443`.
- If webhook validation fails, verify the Plivo V3/V2 signature headers, nonce,
  request method, callback URL, and webhook HMAC secret match the provider
  request.
- If replay handling fails, check that the replay cache only records a nonce
  after a valid signature verdict.

**Rerun commands**:

- `RUN_ID=manual-plivo bash scripts/e2e/plivo_connector_verification.sh`
- `scripts/graduation/run_gauntlet.sh connectors/plivo --jsonl /tmp/fcp-plivo-gauntlet.jsonl`
- `rch exec -- cargo test -p fcp-plivo --test integration plivo_loopback_e2e_jsonl_covers_provider_edges -- --nocapture`

## Verification

Default tests use loopback fixtures only and require no live Plivo credentials.
Run:

```bash
bash scripts/e2e/plivo_connector_verification.sh
```

The verifier prints the JSONL artifact path, SHA-256, and record count from the
Rust test output. The loopback proof covers webhook signature acceptance and
denial, replay handling, inbound allowlist policy, V2 signature fallback,
cancellation and timeout mappings, transient retry, provider error mapping, and
cleanup.

Set `PLIVO_LIVE_E2E=1` to exercise the live-credential preflight. If
`PLIVO_AUTH_ID` or `PLIVO_AUTH_TOKEN` is absent, the script emits a structured
JSONL skip record instead of making network calls.
