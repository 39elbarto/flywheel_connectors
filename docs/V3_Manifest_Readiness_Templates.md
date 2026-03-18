# FCP V3 Manifest, Readiness, Prerequisites, and Network Policy Templates

> **Status**: NORMATIVE
> **Version**: 1.0.0
> **Date**: 2026-03-18
> **Bead Reference**: `flywheel_connectors-j05nu.11.4`
> **Depends On**: `V3_Connector_Acceptance_Contract.md`

---

## Purpose

This document defines the manifest structure, readiness expectations, prerequisite documentation standards, and network policy templates for all FCP V3 connectors. These templates are the retrofit target for existing connectors and the starting point for new ones.

---

## 1. Manifest Template (manifest.toml)

Every connector MUST provide a manifest with the following structure. Fields marked REQUIRED must be present; fields marked OPTIONAL are present when applicable.

```toml
[connector]
id = "your-service"                    # REQUIRED: lowercase, [a-z0-9._:-]+
name = "Your Service Connector"        # REQUIRED: human-readable
version = "0.1.0"                      # REQUIRED: semver
author = "FCP Team"                    # REQUIRED
description = "Brief connector description" # REQUIRED
homepage = ""                          # OPTIONAL: connector docs URL

[connector.archetypes]
# REQUIRED: at least one true
request_response = true
streaming = false
bidirectional = false
polling = false
webhook = false
queue_pubsub = false
file_blob = false
database = false
cli_process = false
browser = false

[connector.state]
model = "stateless"                    # REQUIRED: stateless | singleton_writer | crdt
# crdt_type = "lww_map"               # REQUIRED if model = "crdt"

[connector.execution]
format = "native"                      # REQUIRED: native | wasi | remote_eligible

[connector.budget]
deadline_ms = 30000                    # REQUIRED: max operation duration
# cost_quota = 0                      # OPTIONAL: cost budget per operation

[connector.restart]
strategy = "exponential_backoff"       # REQUIRED: immediate | fixed | exponential_backoff | never
max_restarts = 3                       # REQUIRED
window_ms = 300000                     # REQUIRED: restart count window

[connector.drain]
soft_timeout_ms = 5000                 # REQUIRED: graceful shutdown timeout
hard_timeout_ms = 10000                # REQUIRED: forced shutdown timeout

# --- Capabilities ---

[capabilities]
required = [                           # REQUIRED: capabilities the connector needs
    "your-service.read",
    "your-service.write",
]
optional = []                          # OPTIONAL: capabilities that enhance functionality
forbidden = []                         # OPTIONAL: capabilities the connector must NOT have

# --- Operations ---

[[operations]]
id = "your-service.list_items"
capability = "your-service.read"
safety_tier = "safe"
idempotency = "none"
# input_schema and output_schema referenced by ID

[[operations]]
id = "your-service.create_item"
capability = "your-service.write"
safety_tier = "risky"
idempotency = "strict"

# --- Network Constraints ---

[network]
# REQUIRED: declare all external hosts the connector communicates with
allowed_hosts = ["api.your-service.com"]
allowed_ports = [443]
require_tls = true
# deny_localhost = true               # Default: true
# deny_private = true                 # Default: true (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)

# --- Sandbox ---

[sandbox]
profile = "strict"                     # REQUIRED: strict | strict-plus | moderate | permissive
memory_mb = 128                        # REQUIRED: memory limit
deny_exec = true                       # REQUIRED: prevent child process spawning
deny_ptrace = true                     # REQUIRED: prevent debugging/tracing
# fs_readonly = ["/etc/ssl/certs"]    # OPTIONAL: read-only filesystem paths
# fs_writable = ["/tmp/connector"]    # OPTIONAL: writable paths (state directory)

# --- Provisioning ---

[provisioning]
# REQUIRED: describe how the connector gets its credentials
recipe = "api_key"                     # api_key | oauth | service_account | bridge | none
supports_rotation = true               # REQUIRED: can credentials be rotated without restart?
zero_persist_secrets = true            # REQUIRED: secrets never written to disk?
```

---

## 2. Manifest Variants by Connector Type

### SaaS API Connector

```toml
[network]
allowed_hosts = ["api.service.com"]
allowed_ports = [443]
require_tls = true

[provisioning]
recipe = "api_key"
supports_rotation = true
zero_persist_secrets = true
```

### OAuth-based Connector

```toml
[provisioning]
recipe = "oauth"
supports_rotation = true    # OAuth refresh token flow
zero_persist_secrets = true
# OAuth endpoints declared here for provisioning flow
# oauth_authorize_url = "https://service.com/oauth/authorize"
# oauth_token_url = "https://service.com/oauth/token"
# oauth_scopes = ["read", "write"]
```

### Database Connector (Private Network)

```toml
[network]
allowed_hosts = []          # Empty: configured per-instance
allowed_ports = [5432]      # Default port
require_tls = false         # Often plaintext on private network
deny_localhost = false      # Database may be on localhost
deny_private = false        # Database is typically on private network

[provisioning]
recipe = "connection_string"
supports_rotation = true
zero_persist_secrets = true
```

### Bridge/Daemon Connector (Local Only)

```toml
[network]
allowed_hosts = ["localhost", "127.0.0.1"]
allowed_ports = [8080]      # Bridge HTTP port
require_tls = false
deny_localhost = false      # Bridge IS on localhost
deny_private = true

[provisioning]
recipe = "bridge"
supports_rotation = false   # Bridge manages its own credentials
zero_persist_secrets = true

[prerequisites]
# REQUIRED for bridge connectors
bridge_name = "signal-cli"
bridge_version_min = "0.13.0"
bridge_install_url = "https://github.com/AsamK/signal-cli"
bridge_health_endpoint = "http://localhost:8080/v1/about"
```

### Cloud Control Plane

```toml
[network]
allowed_hosts = ["*.amazonaws.com", "*.googleapis.com"]
allowed_ports = [443]
require_tls = true

[provisioning]
recipe = "service_account"   # Or: iam_role, oauth
supports_rotation = true
zero_persist_secrets = true
```

---

## 3. Readiness and Doctor Expectations

### self_check() / Doctor Contract

Every connector's self_check (doctor) MUST return a structured report covering:

| Check | Required | Description |
|-------|----------|-------------|
| `credentials_valid` | YES | Are stored credentials valid and not expired? |
| `service_reachable` | YES | Can the connector reach the external service? |
| `config_complete` | YES | Are all required configuration fields present? |
| `version_compatible` | If applicable | Is the external service API version compatible? |
| `bridge_running` | If bridge | Is the external bridge/daemon process alive? |
| `bridge_version` | If bridge | Does the bridge version meet minimum requirements? |
| `permissions_sufficient` | If verifiable | Do credentials have the required scopes/permissions? |

### Response Format

```json
{
  "status": "healthy|degraded|unhealthy|not_configured",
  "checks": [
    {
      "name": "credentials_valid",
      "passed": true,
      "message": "API key validated successfully"
    },
    {
      "name": "service_reachable",
      "passed": false,
      "message": "Connection to api.service.com:443 timed out after 5s",
      "remediation": "Check network connectivity. Ensure firewall allows outbound HTTPS to api.service.com."
    }
  ],
  "metrics": {
    "uptime_ms": 3600000,
    "requests_total": 1542,
    "errors_total": 3,
    "last_successful_request_ms_ago": 250
  }
}
```

### Remediation Text Standards

Every failing check MUST include a `remediation` field with operator-actionable instructions:

**Good remediation text**:
- "API key expired. Generate a new key at https://service.com/settings/api-keys and update the connector configuration."
- "signal-cli bridge not running. Start it with: `signal-cli -u +1234567890 daemon --http`"
- "Database connection refused on localhost:5432. Verify PostgreSQL is running: `pg_isready -h localhost`"

**Bad remediation text**:
- "Connection failed" (no action)
- "Error occurred" (no specifics)
- "Check configuration" (which configuration? what specifically?)

---

## 4. Prerequisite Documentation Standard

### For API-based Connectors

Manifest or connector documentation MUST specify:

1. **Where to get credentials**: Direct URL to the provider's API key / OAuth app creation page.
2. **Required scopes/permissions**: Exact list of OAuth scopes or API permissions needed.
3. **Minimum plan/tier**: If the API requires a paid plan, state which tier.
4. **Rate limits**: Known rate limits at the expected plan tier.
5. **Regional restrictions**: If the API is geo-restricted.

### For Bridge-based Connectors

Manifest MUST include a `[prerequisites]` section specifying:

1. **Bridge software**: Name, version, installation URL.
2. **Bridge configuration**: Required bridge config for FCP integration.
3. **Bridge startup command**: Exact command to start the bridge in FCP-compatible mode.
4. **Platform support**: Which OS/architectures the bridge supports.
5. **Storage requirements**: Disk space, database, etc.

### For Self-hosted Connectors

Manifest MUST specify:

1. **Minimum server version**: The external service version required.
2. **API endpoint configuration**: How the operator provides the base URL.
3. **TLS requirements**: Whether self-signed certs are supported.
4. **Admin access required**: Whether initial setup needs admin privileges.

---

## 5. Network Policy Templates

### Template: Public SaaS (Most Common)

```toml
[network]
allowed_hosts = ["api.service.com"]
allowed_ports = [443]
require_tls = true
deny_localhost = true
deny_private = true
```

### Template: Private Database

```toml
[network]
allowed_hosts = []              # Configured per-instance
allowed_ports = [5432]
require_tls = false             # May use plaintext on private network
deny_localhost = false
deny_private = false
```

### Template: Local Bridge

```toml
[network]
allowed_hosts = ["localhost", "127.0.0.1"]
allowed_ports = [8080]
require_tls = false
deny_localhost = false
deny_private = true             # Bridge is local; no reason to hit LAN
```

### Template: Multi-Region Cloud

```toml
[network]
allowed_hosts = [
    "*.amazonaws.com",
    "*.aws.amazon.com",
]
allowed_ports = [443]
require_tls = true
deny_localhost = true
deny_private = true
```

### Template: Google Workspace

```toml
[network]
allowed_hosts = [
    "*.googleapis.com",
    "oauth2.googleapis.com",
    "accounts.google.com",
]
allowed_ports = [443]
require_tls = true
deny_localhost = true
deny_private = true
```

### Template: No Network (Local-Only)

```toml
[network]
allowed_hosts = []
allowed_ports = []
require_tls = false
deny_localhost = true
deny_private = true
# Connector operates on local files/databases only (e.g., SQLite)
```

---

## 6. Sandbox Profile Guidelines

| Profile | When to Use | Constraints |
|---------|-------------|-------------|
| `strict` | Default for all connectors | deny_exec, deny_ptrace, minimal fs access |
| `strict-plus` | Connectors handling credentials | strict + memory isolation + no fs_writable |
| `moderate` | Connectors that need child processes (CLI/process archetype) | deny_ptrace, limited exec, bounded fs |
| `permissive` | Browser connectors (CDP requires process control) | bounded memory, network constrained, fs sandboxed |

### Memory Limits by Archetype

| Archetype | Typical Memory | Rationale |
|-----------|---------------|-----------|
| Request-Response | 64-128 MB | Single request in flight |
| Streaming | 128-256 MB | Connection buffers + event queue |
| Database | 128-256 MB | Connection pool + result buffers |
| Browser | 512-1024 MB | Chromium process overhead |
| File/Blob | 256-512 MB | Chunked transfer buffers |
| CLI/Process | 128-256 MB | Process output capture buffer |

---

## 7. Applying Templates to Existing Connectors

When retrofitting an existing connector:

1. Check if `manifest.toml` exists. If not, create one using the appropriate template.
2. Verify `[network]` constraints match the connector's actual HTTP calls.
3. Verify `[sandbox]` profile matches the connector's actual resource needs.
4. Verify `[provisioning]` accurately describes how credentials are obtained.
5. Verify `self_check()` covers all applicable checks from Section 3.
6. Verify remediation text meets the standards in Section 3.

Any gaps found during retrofit should be filed as remediation items in the audit bead.

---

## Changelog

- **1.0.0** (2026-03-18): Initial manifest, readiness, and network policy templates. Covers manifest structure, archetype-specific variants, doctor contract, prerequisite documentation, network policy templates, sandbox guidelines, and retrofit guidance.
