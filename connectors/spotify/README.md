# Spotify Connector V3 Contract

> **Status**: runtime contract documented; manifest/introspection/API drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Spotify Web API upstream**: https://developer.spotify.com/documentation/web-api
> **Spotify API calls upstream**: https://developer.spotify.com/documentation/web-api/concepts/api-calls
> **Spotify authorization upstream**: https://developer.spotify.com/documentation/web-api/concepts/authorization
> **Spotify search upstream**: https://developer.spotify.com/documentation/web-api/reference/search
> **Spotify playback state upstream**: https://developer.spotify.com/documentation/web-api/reference/get-information-about-the-users-current-playback
> **Spotify library items upstream**: https://developer.spotify.com/documentation/web-api/reference/save-library-items

## Purpose

This document fixes the operator-facing contract for `fcp.spotify`. The connector exposes the Spotify Web API surface implemented in this crate: profile lookup, catalog search, entity metadata reads, user library reads and writes, playlist reads and writes, recently played history, top items, recommendations endpoints, and playback controls.

The connector is intentionally a bounded Spotify Web API bridge. It is not a Spotify SDK wrapper, Web Playback SDK implementation, audio streaming client, cover-art downloader, player-state event bus, token refresh daemon, analytics export pipeline, recommendation engine, or media-ingestion service.

## Current Runtime Snapshot

The current crate exposes these runtime operation IDs:

- `spotify.profile.get`
- `spotify.search`
- `spotify.tracks.get`
- `spotify.albums.get`
- `spotify.artists.get`
- `spotify.playlists.get`
- `spotify.playlists.list`
- `spotify.player.recently_played`
- `spotify.top_items`
- `spotify.recommendations.get`
- `spotify.recommendations.genres`
- `spotify.search.tracks`
- `spotify.search.albums`
- `spotify.search.artists`
- `spotify.search.shows`
- `spotify.search.episodes`
- `spotify.show.get`
- `spotify.show.episodes`
- `spotify.episode.get`
- `spotify.playback.get_state`
- `spotify.playback.devices`
- `spotify.playback.play`
- `spotify.playback.pause`
- `spotify.playback.skip_next`
- `spotify.playback.skip_previous`
- `spotify.playback.seek`
- `spotify.playback.volume`
- `spotify.playback.shuffle`
- `spotify.playback.repeat`
- `spotify.playback.transfer`
- `spotify.library.tracks.list`
- `spotify.library.tracks.save`
- `spotify.library.tracks.remove`
- `spotify.library.tracks.check`
- `spotify.library.albums.list`
- `spotify.library.albums.save`
- `spotify.library.albums.remove`
- `spotify.playlist.create`
- `spotify.playlist.update`
- `spotify.playlist.tracks.list`
- `spotify.playlist.tracks.add`
- `spotify.playlist.tracks.remove`

Important runtime truths the contract preserves:

- Package, library, and binary name are `fcp-spotify`.
- Manifest ID is `fcp.spotify`.
- `BaseConnector` runtime ID is `spotify`.
- Manifest version is `0.1.0`.
- Manifest format is `wasi`.
- Configuration requires exactly one auth source:
  - `access_token`
  - `credential_id`
- Direct token mode sends `Authorization: Bearer <token>`.
- `credential_id` mode sends `X-FCP-Credential-Id: <uuid>` and expects host egress policy to inject real secret material.
- `credential_id` must be a valid UUID.
- Default runtime base URL is `https://api.spotify.com/v1`.
- Runtime configure accepts custom `base_url` values.
- Runtime base URL policy accepts `api.spotify.com`, `accounts.spotify.com`, and loopback hosts for tests.
- Runtime request timeout is 30 seconds.
- Runtime request-context timeout is 30 seconds.
- The client stores a retry config with `max_retries = 2`, but the low-level HTTP helpers send a single request in the current implementation.
- `health()` reports configured/session-ID state, request counters, error counters, and provisioning readiness. It does not call Spotify.
- `doctor()` checks local configuration, client initialization, base URL policy, auth mode, credential-injection readiness, and handshake session ID. It does not call Spotify.
- `self_check()` reports local provisioning readiness only. It does not perform a live Spotify probe.
- Runtime `invoke` uses the JSON field `operation_id`, not `operation`.
- Runtime `invoke` does not require or verify a capability token.
- Runtime `simulate` only checks whether the `operation_id` is known.
- Runtime `simulate` does not check configuration, handshake, input shape, approval policy, provider scopes, or capability tokens.
- Runtime `shutdown()` calls client shutdown, clears config and client state, and clears the base configured/handshaken flags.
- Runtime `shutdown()` does not clear the stored `session_id`.

## Runtime API Adapter

The runtime uses these request shapes under `{base_url}`:

| Operation | Runtime request | Required input | Output handling |
|-----------|-----------------|----------------|-----------------|
| `spotify.profile.get` | `GET /me` | none | Returns `{ "profile": ... }`. |
| `spotify.search` | `GET /search?q={query}&type={types}&limit={limit}` | `query` | `types` defaults to `track`; returns `{ "results": ... }`. |
| `spotify.tracks.get` | `GET /tracks/{track_id}` | `track_id` | Returns `{ "track": ... }`. |
| `spotify.albums.get` | `GET /albums/{album_id}` | `album_id` | Returns `{ "album": ... }`. |
| `spotify.artists.get` | `GET /artists/{artist_id}` | `artist_id` | Returns `{ "artist": ... }`. |
| `spotify.playlists.get` | `GET /playlists/{playlist_id}` | `playlist_id` | Returns `{ "playlist": ... }`. |
| `spotify.playlists.list` | `GET /me/playlists` | none | Returns provider `items` as `playlists`, defaulting to `[]`. |
| `spotify.player.recently_played` | `GET /me/player/recently-played` | none | Validates and normalizes history items, cursors, total, and limit. |
| `spotify.top_items` | `GET /me/top/{item_type}` | `item_type` | `time_range` defaults to `medium_term`; returns provider `items`. |
| `spotify.recommendations.get` | `GET /recommendations` | none | Forwards `seed_artists`, `seed_genres`, and `limit`; returns provider `tracks`. |
| `spotify.recommendations.genres` | `GET /recommendations/available-genre-seeds` | none | Returns provider `genres`. |
| `spotify.search.tracks` | `GET /search?type=track` | `query` | Optional `market`; returns `{ "results": ... }`. |
| `spotify.search.albums` | `GET /search?type=album` | `query` | Optional `market`; returns `{ "results": ... }`. |
| `spotify.search.artists` | `GET /search?type=artist` | `query` | Optional `market`; returns `{ "results": ... }`. |
| `spotify.search.shows` | `GET /search?type=show` | `query` | Optional `market`; returns `{ "results": ... }`. |
| `spotify.search.episodes` | `GET /search?type=episode` | `query` | Optional `market`; returns `{ "results": ... }`. |
| `spotify.show.get` | `GET /shows/{show_id}` | `show_id` | Optional `market`; returns `{ "show": ... }`. |
| `spotify.show.episodes` | `GET /shows/{show_id}/episodes` | `show_id` | `limit` defaults to `20`, `offset` defaults to `0`; returns `items` and `total`. |
| `spotify.episode.get` | `GET /episodes/{episode_id}` | `episode_id` | Optional `market`; returns `{ "episode": ... }`. |
| `spotify.playback.get_state` | `GET /me/player` | none | Returns `{ "state": ... }`. |
| `spotify.playback.devices` | `GET /me/player/devices` | none | Returns provider `devices`, defaulting to `[]`. |
| `spotify.playback.play` | `PUT /me/player/play` | none | Optional `device_id`, `context_uri`, and `uris`; returns `{ "started": true }` after provider success. |
| `spotify.playback.pause` | `PUT /me/player/pause` | none | Optional `device_id`; returns `{ "paused": true }`. |
| `spotify.playback.skip_next` | `POST /me/player/next` | none | Optional `device_id`; returns `{ "skipped": "next" }`. |
| `spotify.playback.skip_previous` | `POST /me/player/previous` | none | Optional `device_id`; returns `{ "skipped": "previous" }`. |
| `spotify.playback.seek` | `PUT /me/player/seek` | none | `position_ms` defaults to `0`; optional `device_id`; returns the target position. |
| `spotify.playback.volume` | `PUT /me/player/volume` | none | `volume_percent` defaults to `50`; optional `device_id`; returns the sent volume. |
| `spotify.playback.shuffle` | `PUT /me/player/shuffle` | none | `state` defaults to `false`; optional `device_id`; returns the sent shuffle state. |
| `spotify.playback.repeat` | `PUT /me/player/repeat` | none | `state` defaults to `off`; optional `device_id`; returns the sent repeat state. |
| `spotify.playback.transfer` | `PUT /me/player` | `device_id` | Sends `device_ids: [device_id]` and optional `play`; returns transfer receipt. |
| `spotify.library.tracks.list` | `GET /me/tracks` | none | `limit` defaults to `20`, `offset` defaults to `0`; returns `items` and `total`. |
| `spotify.library.tracks.save` | `PUT /me/tracks` | `ids` | Sends JSON `{ "ids": ids }`; returns `{ "saved": true }`. |
| `spotify.library.tracks.remove` | `DELETE /me/tracks` with JSON body | `ids` | Sends JSON `{ "ids": ids }`; returns `{ "removed": true }`. |
| `spotify.library.tracks.check` | `GET /me/tracks/contains?ids=...` | `ids` | Returns provider boolean array as `results`. |
| `spotify.library.albums.list` | `GET /me/albums` | none | `limit` defaults to `20`, `offset` defaults to `0`; returns `items` and `total`. |
| `spotify.library.albums.save` | `PUT /me/albums` | `ids` | Sends JSON `{ "ids": ids }`; returns `{ "saved": true }`. |
| `spotify.library.albums.remove` | `DELETE /me/albums` with JSON body | `ids` | Sends JSON `{ "ids": ids }`; returns `{ "removed": true }`. |
| `spotify.playlist.create` | `POST /users/{user_id}/playlists` | `user_id`, `name` | `public` defaults to `false`; returns `{ "playlist": ... }`. |
| `spotify.playlist.update` | `PUT /playlists/{playlist_id}` | `playlist_id` | Sends optional `name`, `public`, and `description`; returns `{ "updated": true }`. |
| `spotify.playlist.tracks.list` | `GET /playlists/{playlist_id}/tracks` | `playlist_id` | `limit` defaults to `20`, `offset` defaults to `0`; returns `items` and `total`. |
| `spotify.playlist.tracks.add` | `POST /playlists/{playlist_id}/tracks` | `playlist_id`, `uris` | Optional `position`; returns `snapshot_id` when present. |
| `spotify.playlist.tracks.remove` | `DELETE /playlists/{playlist_id}/tracks` with JSON body | `playlist_id`, `uris` | Returns `snapshot_id` when present. |

Path and query handling:

- `query` strings are encoded with a small local encoder for `%`, space, `&`, `=`, `+`, and `#`.
- IDs and URI values are inserted directly into paths, query strings, or JSON bodies without full URL/path validation.
- `limit`, `offset`, `position_ms`, and `volume_percent` values are not clamped to the manifest schema maximums before request construction.
- The generic search runtime input uses `types`, while the manifest documents `type`.
- The generic search runtime does not forward `market`, while the manifest documents `market`.
- Typed search operations forward optional `market`.
- Playback control operations return local boolean/string receipts after provider success; they do not fetch state to confirm the visible player result.
- Empty Spotify success bodies become `{}` at the client layer.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Spotify documents the Web API base address as `https://api.spotify.com`. Runtime correctly defaults to `https://api.spotify.com/v1`.
- Spotify Web API calls require authorization, and private user data requires user permission scopes. Runtime accepts an already-issued access token or host credential reference and does not verify scopes before invoking operations.
- The provisioning recipe models OAuth authorization-code with PKCE and stores `spotify_access_token`, but the crate does not implement token refresh.
- Manifest operation IDs and runtime operation IDs are inconsistent:
  - Manifest has singular IDs such as `spotify.track.get`, `spotify.album.get`, `spotify.artist.get`, and `spotify.playlist.get`.
  - Runtime uses plural IDs such as `spotify.tracks.get`, `spotify.albums.get`, `spotify.artists.get`, and `spotify.playlists.get`.
  - Manifest has legacy single-track library aliases `spotify.library.list_saved_tracks`, `spotify.library.save_track`, and `spotify.library.remove_track`.
  - Runtime uses batch-style IDs such as `spotify.library.tracks.list`, `spotify.library.tracks.save`, and `spotify.library.tracks.remove`.
  - Manifest declares `spotify.player.stream` and `spotify.media.download_cover`, but runtime does not implement those operations.
  - Runtime exposes `spotify.profile.get`, `spotify.player.recently_played`, `spotify.top_items`, and `spotify.recommendations.get`, which are not represented in the manifest operation catalog.
- Manifest optional capabilities include `spotify.playback.write`, but runtime introspection uses `spotify.playback.control` for playback mutations.
- Handshake returns only `spotify.read` after configure even though runtime can dispatch playback, library, playlist, and recommendation operations.
- Handshake does not parse a full `HandshakeRequest`, does not install a `CapabilityVerifier`, and does not return a manifest hash.
- Runtime `invoke` does not require capability tokens or approval tokens.
- Runtime introspection reports no `requires_approval` metadata for playback, library, or playlist mutations.
- Manifest rate-limit pools exist for read, library, playback, stream, media, and playlist operations. Runtime introspection reports no rate-limit metadata and the client does not enforce those pools.
- Manifest response caps vary by operation. Runtime does not enforce those response byte caps before parsing JSON.
- Spotify search docs carry policy notes that Spotify content may not be used to train an AI model. The runtime does not enforce downstream data-use restrictions.
- Spotify playback docs carry policy restrictions for playback-state and playback-control use. The runtime does not enforce those provider-policy constraints beyond operation naming and capability metadata.
- Spotify currently marks `GET /recommendations/available-genre-seeds` deprecated in the official reference. Runtime still exposes `spotify.recommendations.genres`.
- Spotify currently marks older saved-track endpoints such as `/me/tracks` as deprecated in favor of the newer library item endpoints. Runtime still uses `/me/tracks` for saved-track list/save/remove/check.
- `self_check()` reports local readiness without a live read-only Spotify API probe.
- Runtime `simulate` is only a known-operation check.
- `credential_id` mode is accepted and invokes send `X-FCP-Credential-Id`; without an egress proxy, calls to Spotify itself will not be authenticated.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should reconcile manifest IDs with runtime IDs, remove or implement stream/media operations, align playback capability names, filter granted capabilities during handshake, add capability-token and approval-token verification, enforce or surface provider scopes, migrate deprecated Spotify endpoints where needed, add token refresh, and add live self-check behavior.

## First-Slice Scope

The current Spotify README slice documents the existing runtime surface:

- access-token and credential-ID configuration
- OAuth PKCE provisioning recipe shape and token-refresh gap
- profile, search, catalog, podcast, playback, library, playlist, history, top-items, and recommendations operations
- lifecycle, doctor, health, self-check, simulate, introspect, invoke, and shutdown behavior
- provider error mapping, timeout behavior, query encoding, and input normalization
- runtime/manifest/provider-doc drift around operation IDs, capabilities, streaming/media declarations, deprecated endpoints, approvals, rate limits, response caps, scopes, and capability-token verification
- deterministic WireMock integration tests

## Auth And Zone Boundary

- Authentication mechanisms: direct Spotify access token or host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zone: `z:public`.
- Runtime capability families:
  - `spotify.read`
  - `spotify.playback.read`
  - `spotify.playback.control`
  - `spotify.library.read`
  - `spotify.library.write`
  - `spotify.playlists.read`
  - `spotify.playlists.write`
- Manifest required capabilities are `network.dns`, `network.egress`, `network.tls.sni`, and `storage.state`.
- Manifest forbids `system.exec` and `network.listen`.
- The connector does not intentionally persist access tokens, credential IDs beyond configuration metadata, Spotify payloads, playback state, request counters, or error counters outside process memory.
- Spotify payloads can contain account profile data, email addresses, playback state, device IDs, recently played history, library contents, playlist contents, and podcast/track metadata. Treat live output as private or work-zone sensitive data unless the host supplies a stricter zone policy.
- Audit helper modules in this crate are designed to avoid leaking names in history, library, and playback audit events, but the main connector runtime returns provider payloads to callers.

## Network And Runtime Invariants

- Default runtime base URL: `https://api.spotify.com/v1`.
- Direct token requests use `Authorization: Bearer <token>`.
- `credential_id` requests use `X-FCP-Credential-Id: <uuid>`.
- Runtime base URL policy accepts `https://api.spotify.com`, `https://accounts.spotify.com`, and loopback hosts for tests.
- Runtime base URL policy rejects non-local `http` and unknown hosts.
- Runtime client timeout is 30 seconds.
- Runtime request-context timeout is 30 seconds.
- Manifest operation network policy allows `api.spotify.com` on port `443`, requires TLS/SNI, denies localhost, private ranges, tailnet ranges, and IP literals, and caps redirects at zero.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `300000 ms` wall-clock timeout, no exec, no ptrace, read-only `/usr` and `/lib`, and writable `$CONNECTOR_STATE`.
- The connector does not open inbound sockets.
- Provider 401 and 403 are terminal authentication or authorization failures.
- Provider 404 is a terminal not-found failure.
- Provider 429 is retryable and honors `Retry-After` seconds, defaulting to 60 seconds when absent.
- Other non-success provider responses are external API errors.
- JSON parse errors are internal failures.

## Capability Families

| Capability | Purpose |
|------------|---------|
| `spotify.read` | Read profile, catalog metadata, search results, podcasts, history, top items, and recommendation data. |
| `spotify.playback.read` | Read playback state and available devices. |
| `spotify.playback.control` | Start, pause, seek, transfer, skip, shuffle, repeat, or change volume. |
| `spotify.library.read` | Read saved tracks and albums or check saved-track membership. |
| `spotify.library.write` | Save or remove tracks and albums in the current user's library. |
| `spotify.playlists.read` | List playlist items. |
| `spotify.playlists.write` | Create playlists, update playlist details, and add/remove playlist tracks. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `spotify.profile.get` | `GET /me` | `spotify.read` | `Safe` | `Low` | `Strict` | Reads the current user profile. |
| `spotify.search` | `GET /search` | `spotify.read` | `Safe` | `Low` | `Strict` | Reads catalog search results. |
| `spotify.tracks.get` | `GET /tracks/{track_id}` | `spotify.read` | `Safe` | `Low` | `Strict` | Reads one track. |
| `spotify.albums.get` | `GET /albums/{album_id}` | `spotify.read` | `Safe` | `Low` | `Strict` | Reads one album. |
| `spotify.artists.get` | `GET /artists/{artist_id}` | `spotify.read` | `Safe` | `Low` | `Strict` | Reads one artist. |
| `spotify.playlists.get` | `GET /playlists/{playlist_id}` | `spotify.read` | `Safe` | `Low` | `Strict` | Reads one playlist. |
| `spotify.playlists.list` | `GET /me/playlists` | `spotify.read` | `Safe` | `Low` | `Strict` | Reads current user playlists. |
| `spotify.player.recently_played` | `GET /me/player/recently-played` | `spotify.read` | `Safe` | `Low` | `Strict` | Reads playback history and normalizes privacy-sensitive fields. |
| `spotify.top_items` | `GET /me/top/{item_type}` | `spotify.read` | `Safe` | `Low` | `Strict` | Reads current user top artists or tracks. |
| `spotify.recommendations.get` | `GET /recommendations` | `spotify.read` | `Safe` | `Low` | `Strict` | Reads provider recommendation tracks. |
| `spotify.recommendations.genres` | `GET /recommendations/available-genre-seeds` | `spotify.read` | `Safe` | `Low` | `Strict` | Reads provider genre seed list. |
| `spotify.search.tracks` | `GET /search?type=track` | `spotify.read` | `Safe` | `Low` | `Strict` | Reads track search results. |
| `spotify.search.albums` | `GET /search?type=album` | `spotify.read` | `Safe` | `Low` | `Strict` | Reads album search results. |
| `spotify.search.artists` | `GET /search?type=artist` | `spotify.read` | `Safe` | `Low` | `Strict` | Reads artist search results. |
| `spotify.search.shows` | `GET /search?type=show` | `spotify.read` | `Safe` | `Low` | `Strict` | Reads show search results. |
| `spotify.search.episodes` | `GET /search?type=episode` | `spotify.read` | `Safe` | `Low` | `Strict` | Reads episode search results. |
| `spotify.show.get` | `GET /shows/{show_id}` | `spotify.read` | `Safe` | `Low` | `Strict` | Reads one podcast show. |
| `spotify.show.episodes` | `GET /shows/{show_id}/episodes` | `spotify.read` | `Safe` | `Low` | `Strict` | Reads show episodes. |
| `spotify.episode.get` | `GET /episodes/{episode_id}` | `spotify.read` | `Safe` | `Low` | `Strict` | Reads one podcast episode. |
| `spotify.playback.get_state` | `GET /me/player` | `spotify.playback.read` | `Safe` | `Low` | `Strict` | Reads current playback state. |
| `spotify.playback.devices` | `GET /me/player/devices` | `spotify.playback.read` | `Safe` | `Low` | `Strict` | Reads Spotify Connect devices. |
| `spotify.playback.play` | `PUT /me/player/play` | `spotify.playback.control` | `Risky` | `Medium` | `BestEffort` | Starts or resumes playback. |
| `spotify.playback.pause` | `PUT /me/player/pause` | `spotify.playback.control` | `Risky` | `Low` | `BestEffort` | Pauses playback. |
| `spotify.playback.skip_next` | `POST /me/player/next` | `spotify.playback.control` | `Risky` | `Low` | `BestEffort` | Skips queue position. |
| `spotify.playback.skip_previous` | `POST /me/player/previous` | `spotify.playback.control` | `Risky` | `Low` | `BestEffort` | Rewinds queue position. |
| `spotify.playback.seek` | `PUT /me/player/seek` | `spotify.playback.control` | `Risky` | `Low` | `BestEffort` | Changes playback position. |
| `spotify.playback.volume` | `PUT /me/player/volume` | `spotify.playback.control` | `Risky` | `Medium` | `BestEffort` | Changes device volume. |
| `spotify.playback.shuffle` | `PUT /me/player/shuffle` | `spotify.playback.control` | `Risky` | `Low` | `BestEffort` | Changes shuffle mode. |
| `spotify.playback.repeat` | `PUT /me/player/repeat` | `spotify.playback.control` | `Risky` | `Low` | `BestEffort` | Changes repeat mode. |
| `spotify.playback.transfer` | `PUT /me/player` | `spotify.playback.control` | `Risky` | `Medium` | `BestEffort` | Transfers active playback to another device. |
| `spotify.library.tracks.list` | `GET /me/tracks` | `spotify.library.read` | `Safe` | `Low` | `Strict` | Reads saved tracks. |
| `spotify.library.tracks.save` | `PUT /me/tracks` | `spotify.library.write` | `Risky` | `Low` | `Strict` | Saves tracks. |
| `spotify.library.tracks.remove` | `DELETE /me/tracks` | `spotify.library.write` | `Risky` | `Medium` | `Strict` | Removes saved tracks. |
| `spotify.library.tracks.check` | `GET /me/tracks/contains` | `spotify.library.read` | `Safe` | `Low` | `Strict` | Checks saved-track membership. |
| `spotify.library.albums.list` | `GET /me/albums` | `spotify.library.read` | `Safe` | `Low` | `Strict` | Reads saved albums. |
| `spotify.library.albums.save` | `PUT /me/albums` | `spotify.library.write` | `Risky` | `Low` | `Strict` | Saves albums. |
| `spotify.library.albums.remove` | `DELETE /me/albums` | `spotify.library.write` | `Risky` | `Medium` | `Strict` | Removes saved albums. |
| `spotify.playlist.create` | `POST /users/{user_id}/playlists` | `spotify.playlists.write` | `Risky` | `Medium` | `BestEffort` | Creates a playlist. |
| `spotify.playlist.update` | `PUT /playlists/{playlist_id}` | `spotify.playlists.write` | `Risky` | `Medium` | `BestEffort` | Updates playlist metadata. |
| `spotify.playlist.tracks.list` | `GET /playlists/{playlist_id}/tracks` | `spotify.playlists.read` | `Safe` | `Low` | `Strict` | Reads playlist items. |
| `spotify.playlist.tracks.add` | `POST /playlists/{playlist_id}/tracks` | `spotify.playlists.write` | `Risky` | `Low` | `BestEffort` | Adds playlist tracks. |
| `spotify.playlist.tracks.remove` | `DELETE /playlists/{playlist_id}/tracks` | `spotify.playlists.write` | `Risky` | `Medium` | `BestEffort` | Removes playlist tracks. |

## Resource URIs

Runtime invoke currently does not verify capability tokens, so no resource binding is enforced locally. The effective authorization boundary is host-side admission plus operation dispatch.

Follow-up work should add resource URI shapes such as:

| Operation family | Candidate resource URI shape |
|------------------|------------------------------|
| Profile | `spotify://me` |
| Catalog items | `spotify://catalog/{kind}/{id}` |
| Playback devices | `spotify://player/device/{device_id}` |
| Library items | `spotify://me/library/{kind}/{id}` |
| Playlists | `spotify://playlist/{playlist_id}` |

## Explicit Non-Goals

The current implementation does not include:

- Spotify Web Playback SDK support
- Audio streaming or streaming subscriptions
- Album-art or podcast-art download
- Real-time player-state events
- OAuth token refresh
- Client-credentials provisioning
- Scope discovery or scope enforcement
- Capability-token or approval-token enforcement
- Full URL/path validation for Spotify IDs
- Migration to the newer unified library item endpoints
- Enforcement of Spotify content attribution or AI-training restrictions

## Verification

README-only changes do not require Cargo or `rch` compilation. For this connector contract, use:

```bash
git diff --check -- connectors/spotify/README.md
LC_ALL=C rg -n '[^ -~]' connectors/spotify/README.md
rg -n '\bmaster\b' connectors/spotify/README.md
ubs connectors/spotify/README.md
```
