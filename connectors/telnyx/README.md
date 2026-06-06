# Telnyx Connector

> **Status**: PROVEN runtime contract documented with remote loopback voice-call verifier proof
> **Verification script**: `scripts/e2e/telnyx_connector_verification.sh`
> **Proof**: `target/fcp-telnyx/purple-telnyx-final-20260606T085500Z/e2e/fcp-telnyx-e2e-3167437-1780736757145839306/telnyx_voice_call_e2e.jsonl`, sha256 `6fa2f5f0f0eb0b216ab3fe9eb8b34821c48edcac733d0d8bf0948e104d44a86b`, 11 redaction-scanned records, rch remote `vmi1149989`

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
- Runtime handshake returns a SHA-256 hash of the bundled `manifest.toml`.
- E2E logs hash or mask call IDs and phone numbers and must never include full E.164 numbers, API keys, auth tokens, raw audio, transcripts, or full webhook bodies.

## Operator Guidance

- Treat Telnyx API keys, credential IDs, callback binding tokens, full E.164
  phone numbers, raw webhook bodies, media, transcripts, provider error
  bodies, and callback URLs as sensitive.
- Verification output should use operation IDs, status/error classes,
  retry decisions, signature verdicts, redacted call/session hashes,
  masked caller identity, and JSONL artifact path/hash summaries.

**Common remediation**:

- If configuration fails, provide either direct in-memory `api_key` or
  secretless `credential_id` mode through the FCP egress layer.
- If provider calls fail in production, confirm the effective base URL is
  `https://api.telnyx.com/v2` and that host egress is limited to
  `api.telnyx.com:443`.
- If webhook validation fails, verify `Telnyx-Signature-Ed25519`,
  `Telnyx-Timestamp`, replay-window policy, and the configured public key match
  the provider request.
- If replay handling fails, check that the replay cache only records an event
  after a valid signature verdict.

**Rerun commands**:

- `RUN_ID=manual-telnyx bash scripts/e2e/telnyx_connector_verification.sh`
- `scripts/graduation/run_gauntlet.sh connectors/telnyx --jsonl /tmp/fcp-telnyx-gauntlet.jsonl`
- `rch exec -- cargo test -p fcp-telnyx --test integration telnyx_loopback_e2e_jsonl_covers_provider_edges -- --nocapture`

## Verification

Default verification requires no live Telnyx credentials:

```bash
bash scripts/e2e/telnyx_connector_verification.sh
```

The verifier prints the JSONL artifact path, SHA-256, and record count from the
Rust test output. The loopback proof covers webhook signature acceptance and
denial, replay handling, inbound allowlist policy, malformed payload handling,
cancellation and timeout mappings, transient retry, provider error mapping, and
cleanup.
