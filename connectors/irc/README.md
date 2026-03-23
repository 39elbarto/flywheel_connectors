# IRC Connector V3 Contract

## Purpose

`fcp-irc` is a bounded IRC connector for short-lived connect, register, join, send, transcript-sample, and health-check flows.

The connector is intentionally narrow. It favors one-shot operator or agent actions over long-lived presence, streaming, or automation that would blur community boundaries.

## Runtime Model

- Each operation opens one IRC session, performs a bounded action, and then sends `QUIT`.
- Authentication is limited to optional `PASS` followed by `NICK` and `USER`.
- TLS is supported and defaults to port `6697`; plaintext defaults to `6667`.
- The connector keeps no durable local state.

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
- The manifest intentionally leaves `host_allow` open because IRC deployments may be public, self-hosted, tailnet-local, or deterministic localhost harnesses.
- The execution boundary is still narrow: ports stay limited to `6667` and `6697`, requests are short-lived, and hostname canonicalization plus bounded timeouts remain required.
- `localhost` and `127.0.0.1` are for deterministic harnesses; production operators should point the connector at an explicitly chosen IRC server.

## Operation Inventory

| Operation | Capability | Purpose |
| --- | --- | --- |
| `irc.messages.send` | `irc.messages.write` | Send one `PRIVMSG` to a channel or nick |
| `irc.channels.join` | `irc.channels.write` | Join one channel, optionally with a key |
| `irc.transcript.sample` | `irc.messages.read` | Collect a bounded sample of recent IRC lines |
| `irc.health` | `irc.health.read` | Verify registration and connectivity |

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

## Operator Notes

- Prefer dedicated bot or service identities for automation instead of a human nick.
- Treat channel names, nicknames, message content, and sampled transcripts as potentially sensitive community data.
- Run `irc.health` before `irc.channels.join` or `irc.messages.send` when validating a fresh configuration.
