# Secretless Connector Migration

Use this runbook when moving a connector from direct secret ownership to
host-owned credential injection.

## Runtime Contract

Connector configuration should carry a `credential_id` reference instead of raw
secret bytes. The connector may put that reference in the egress request metadata
or an `X-FCP-Credential-ID` header, but it must not construct an
`Authorization` header from raw token material.

The host or sandbox egress boundary owns materialization:

1. The connector emits an egress request with `credential_id`.
2. `EgressGuard::authorize_http` validates network constraints and the
   operation's credential allow list.
3. `SecretFetchCredentialInjector` calls the production `SecretFetchHook` once
   for that request.
4. The injector replaces any connector-supplied `Authorization` header with
   `Authorization: Bearer <secret>`.
5. The returned `ZeroizingSecret` is dropped before control returns to connector
   code.

## Connector Checklist

- Accept `credential_id` as the production auth path.
- Reject raw secret configuration fields such as `token`, `access_token`,
  `app_token`, `client_secret`, and `refresh_token` before materializing any
  auth source. Return `FcpError::ConfigurationLeakedSecret` with only the
  SHA-256 hash of the offending field name.
- Keep diagnostics redaction-safe: expose auth mode and credential-id correlation
  only, never secret bytes.
- Report doctor/self-check as degraded when configured with `credential_id` but
  running without the host egress injection layer.
- Add `secretless: true` to introspection output when the connector supports the
  secretless path.
- Test the egress boundary with a `SecretFetchHook` implementation and assert one
  fetch per request.

## Representative Shapes

- GitHub stable bearer: `credential_id` resolves to a personal access token or
  installation token and injects a bearer header for REST requests.
- Slack bot OAuth bearer: `credential_id` resolves to the `xoxb-*` bot token and
  injects a bearer header for Web API requests.
- Slack Socket Mode bearer: use a separate `socket_mode_credential_id` when the
  connector needs an app-level token for `apps.connections.open`; never accept a
  raw `app_token`.
- Gmail OAuth bearer: `credential_id` resolves to a host-managed OAuth access
  token and injects a bearer header for Google REST requests. Refresh-token
  rotation must happen in the host credential backend, then subsequent requests
  fetch the rotated access token through `SecretFetchHook`.

## Proof Expectations

For each migrated connector, keep a smoke test that builds the connector-shaped
egress request with only `credential_id`, runs it through `EgressGuard` plus
`SecretFetchCredentialInjector`, and asserts:

- no raw secret is present before authorization;
- the credential id is allowed for the operation;
- the destination host is allowed for the credential;
- exactly one hook fetch happens per request;
- the final request carries `Authorization: Bearer <secret>`.
