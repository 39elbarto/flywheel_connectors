# IRC Connector V3 Contract

> **Status**: PROVEN runtime contract documented with remote IRC local no-mock verifier proof
> **Bead**: `flywheel_connectors-angoc.16.5`
> **Verification script**: `scripts/e2e/irc_connector_verification.sh`
> **Proof**: `/tmp/fcp-irc-proof3-20260606T125732Z/irc_connector_verification.jsonl`, sha256 `cbe8beec7c96449ac5385ed20c019815583a454c4858189d56b184583dddd0af`, 7 redaction-scanned records, rch remote `vmi1293453`
> **Primary upstream**: https://modern.ircdocs.horse/

## Purpose

`fcp-irc` is a bounded IRC connector for short-lived connect, register, join, send, transcript-sample, and health-check flows.

The connector preserves raw IRC lines, but read-oriented operations now also return normalized event metadata so agents can reason about numerics, source identity, and channel-versus-private routing without reparsing protocol text themselves.

The connector is intentionally narrow. It favors one-shot operator or agent actions over long-lived presence, streaming, or automation that would blur community boundaries.

## Runtime Model

- Each operation opens one IRC session, performs a bounded action, and then sends `QUIT`.
- Authentication is limited to optional `PASS` followed by `NICK` and `USER`.
- TLS is supported and defaults to port `6697`; plaintext defaults to `6667`.
- The connector keeps no durable local state.
- `irc.messages.send` claims chat ownership before opening the short-lived send session. Duplicate active owners return `FcpError::Unauthorized` code `4090` before provider I/O, and successful sends include redaction-safe `coordination` audit records.
- `irc.channels.join`, `irc.transcript.sample`, and `irc.health` expose both raw transcript lines and normalized event records for IRC numerics and message routing.
- `irc.transcript.sample` returns at most the requested post-join lines and may legitimately return fewer when the channel is quiet.

## Auth Boundary

- One configured connector instance is bound to one IRC server plus one configured IRC identity.
- The identity boundary is `server + port + tls + nick + username + realname + optional password`.
- The connector does not manage nickserv flows, SASL negotiation, bouncer sessions, or multiple simultaneous identities.
- The connector does not persist a long-lived authenticated session between operations.

## Capability Gates

- `irc.messages.write` gates `irc.messages.send`.
- `irc.channels.write` gates `irc.channels.join`.
- `irc.messages.read` gates `irc.transcript.sample`.
- `irc.health.read` gates `irc.health`.
- The connector also requires `network.dns`, `network.egress`, and `network.tls.sni`, and it explicitly forbids `system.exec`, `system.privileged`, and `network.listen`.

## Network And Server Policy

- One connector instance is bound to one operator-configured IRC server and does not multiplex requests across multiple networks.
- The manifest uses runtime-injected `${irc_server_host}` host policy because operators choose the IRC network at deployment time.
- The execution boundary is narrow: ports stay limited to `6667` and `6697`; localhost, private ranges, tailnet ranges, and IP literals are denied; SNI, hostname canonicalization, and bounded timeouts remain required.
- `localhost` and `127.0.0.1` are limited to deterministic connector tests and are not part of the PROVEN provider egress contract.

## Operation Inventory

| Operation | Capability | Purpose |
| --- | --- | --- |
| `irc.messages.send` | `irc.messages.write` | Send one `PRIVMSG` to a channel or nick |
| `irc.channels.join` | `irc.channels.write` | Join one channel, optionally with a key |
| `irc.transcript.sample` | `irc.messages.read` | Collect a bounded sample of recent IRC lines plus normalized event metadata |
| `irc.health` | `irc.health.read` | Verify registration and connectivity |

## Chat Coordination

- `chat_coordination` supports `enabled`, `ttl_seconds`, `fail_open`, `allowlist_channels`, `backend`, and `dm_mode`.
- IRC has no native thread identifier for plain `PRIVMSG`; the target channel or nick is used as the redacted conversation/thread key unless DM mode is set to `skip`.
- Coordination audit records intentionally omit raw nicknames, channel names, and message text.

## Safety Matrix

| Operation | Safety Tier | Risk Level | Why |
| --- | --- | --- | --- |
| `irc.messages.send` | `risky` | `medium` | Produces a visible message in a community or direct IRC target |
| `irc.channels.join` | `risky` | `medium` | Produces a visible join event and may affect channel presence |
| `irc.transcript.sample` | `safe` | `low` | Reads a bounded sample and then disconnects |
| `irc.health` | `safe` | `low` | Checks registration/connectivity without sending a community message |

## Scope Notes

- This first slice uses short-lived IRC sessions per operation.
- Sampling is bounded and does not expose a replay buffer or subscription surface.
- Read-oriented outputs preserve raw lines while also surfacing parsed numerics, source identity, and channel/private route classification.
- Production use is expected to target one explicitly configured IRC server on standard ports.

## Moderation Boundary

- The connector can join, send, sample, and health-check as one configured IRC identity, but it does not model operator or moderator powers.
- It does not expose kick, ban, invite, mode changes, channel administration, NickServ recovery, or server-operator actions.
- Community-visible actions stay limited to join and `PRIVMSG`, and both are intentionally classified as `risky`.

## Explicit Non-Goals

- Long-lived event streams or persistent subscriptions
- SASL, NickServ orchestration, or bouncer lifecycle management
- DCC, file transfer, CTCP expansion, or operator moderation tooling
- Multi-network brokering or cross-server relaying

## Operator Guidance

- Prefer dedicated bot or service identities for automation instead of a human nick.
- Treat channel names, nicknames, message content, and sampled transcripts as potentially sensitive community data.
- Run `irc.health` before `irc.channels.join` or `irc.messages.send` when validating a fresh configuration.

## Verification Surface

The tracked verification entry point is `scripts/e2e/irc_connector_verification.sh`. It runs the IRC crate check, formatting check, explicit `local_non_mock` loopback target, full connector test suite, clippy, and a redaction scan over the generated evidence. The script requires remote `rch` proof for Cargo-backed lanes; if no admissible worker is available, it emits `infra_blocked` rather than treating local fallback as proof.

Promotion proof `purple-irc-proof3-20260606T125732Z` passed the tracked verifier with accepted remote Cargo proof for `cargo_check`, `local_non_mock`, `connector_tests`, and `clippy`, plus source-state formatting and local redaction scan checks.

Rerun commands:

- `env -u CARGO_TARGET_DIR RUN_ID=manual-irc bash scripts/e2e/irc_connector_verification.sh`
- `scripts/graduation/run_gauntlet.sh connectors/irc`
