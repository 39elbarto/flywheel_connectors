# Microsoft Foundry Connector

`fcp.microsoft-foundry` is the direct Microsoft Foundry / Azure OpenAI v1 provider connector. It is separate from `microsoft365` Graph, generic `azure`, and `azure-speech`.

## Operations

- `microsoft_foundry.responses.create`
- `microsoft_foundry.responses.cancel`
- `microsoft_foundry.responses.input_items.list`
- `microsoft_foundry.chat.completions`
- `microsoft_foundry.chat.completions_stream`
- `microsoft_foundry.embeddings.create`
- `microsoft_foundry.deployments.list`
- `microsoft_foundry.health`

## Configuration

Required:

- `base_url`: `https://<resource>.openai.azure.com/openai/v1` or `https://<resource>.services.ai.azure.com/openai/v1`
- exactly one of `api_key`, `entra_access_token`, or `credential_id`

Optional:

- `credential_auth_policy`: `entra_bearer` or `api_key`; defaults to `entra_bearer`
- `default_model`: the deployment name to use when an operation omits `model`
- `request_timeout_ms`
- `model_cache_ttl_seconds`
- `wait_on_rate_limit_ms`

`credential_id` mode is the production path for host-owned credential injection. Entra credential references request the `https://ai.azure.com/.default` token scope from the host credential broker. The connector never shells out to Azure CLI on production invocation paths.

## Security Boundaries

- The `model` field is a Foundry deployment name, not an Azure resource path.
- Logs and e2e artifacts must not contain prompts, completions, embedding vectors, API keys, bearer tokens, tenant IDs, raw resource IDs, or full resource hostnames.
- The connector allows loopback HTTP only for deterministic fixture tests. Production endpoints require HTTPS, SNI, and Microsoft Foundry/Azure OpenAI hosts.
- Microsoft Graph, Azure resource management, and Azure Speech stay in their own connectors.

## Proof Lane

Focused implementation proof:

```bash
cargo fmt --package fcp-microsoft-foundry --check
cargo test -p fcp-microsoft-foundry --all-targets -- --nocapture
cargo check -p fcp-microsoft-foundry --all-targets
cargo clippy -p fcp-microsoft-foundry --all-targets --no-deps -- -D warnings
scripts/e2e/microsoft_foundry_connector_verification.sh
ubs connectors/microsoft-foundry scripts/e2e/microsoft_foundry_connector_verification.sh Cargo.toml
```

Shared-session proof should run the Cargo commands through `rch` with a connector-specific `CARGO_TARGET_DIR`.
