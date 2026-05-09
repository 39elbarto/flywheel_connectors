# Anthropic Vertex Connector

`fcp-anthropic-vertex` is a separate FCP connector for Claude on Google Vertex AI. It is not an extension of the direct `connectors/anthropic` API-key connector: Vertex uses Google auth, Google project/location routing, and model-in-URL `rawPredict` / `streamRawPredict` endpoints.

## Supported Runtime Auth

- `access_token`: an in-memory Google bearer token.
- `oauth_refresh`: refresh-token materialization through the shared `fcp-google-discovery` auth substrate.
- `credential_id`: the preferred secretless FCP path, where an egress proxy injects Google credentials.

Application Default Credentials, metadata-server discovery, credentials files, and default credential chains are provisioning-time concerns in this repo. Runtime configuration rejects those sources and expects the host to materialize either a `credential_id` or an ephemeral bearer token before `configure`.

## Operations

- `anthropic_vertex.messages.create`: POST to `.../models/{model}:rawPredict`.
- `anthropic_vertex.messages.stream`: POST to `.../models/{model}:streamRawPredict` and decode SSE data events into JSON-friendly records.
- `anthropic_vertex.models.normalize`: normalize direct-style Claude aliases to Vertex model ids.
- `anthropic_vertex.health`: return local readiness without touching live Vertex endpoints.

The connector inserts `anthropic_version = "vertex-2023-10-16"` into the JSON body and removes `model` / `model_id` from the payload because Vertex carries the model in the endpoint path. Anthropic beta headers are rejected on this surface; thinking and prompt-cache payload fields are allowed as body fields subject to Vertex support.

## Configuration

```json
{
  "project_id": "my-gcp-project",
  "location": "us-east5",
  "access_token": "ya29...",
  "quota_project_id": "billing-project",
  "retry": {
    "max_retries": 2,
    "initial_delay_ms": 100,
    "max_delay_ms": 1000,
    "jitter_enabled": false
  }
}
```

`location` defaults to `global`. For loopback tests, `base_url` may point to `http://127.0.0.1:<port>`; production endpoints must use HTTPS.

## Verification

Focused proof for this connector:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-anthropic-vertex-swiftwren cargo test -p fcp-anthropic-vertex --test integration -- --nocapture
rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-anthropic-vertex-swiftwren cargo clippy -p fcp-anthropic-vertex --all-targets --no-deps -- -D warnings
rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-anthropic-vertex-swiftwren cargo fmt -p fcp-anthropic-vertex -- --check
```
