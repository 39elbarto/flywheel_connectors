# Google Slides Connector

Status: **INCUBATING**. Offline validation is complete only after the verifier passes. Promotion and live acceptance remain separate gates.

## Scope

The connector exposes five typed operations:

| Operation | Capability | Safety | Behavior |
|---|---|---|---|
| `slides.get` | `slides.read` | Safe | Reads compact presentation metadata and a bounded text page. |
| `slides.pages.get` | `slides.read` | Safe | Reads one slide, notes page, master, or layout. |
| `slides.pages.get_thumbnail` | `slides.read` | Safe | Returns bounded PNG metadata and a short-lived authenticated content URL. |
| `slides.create` | `slides.write` | Risky | Creates once and directly reads metadata back. |
| `slides.batch_update` | `slides.write` | Dangerous | Applies an atomic, typed, revision-guarded batch. |

Drive remains responsible for presentation-file placement, sharing, export, quarantine, restoration, and lifecycle. This connector cannot delete or trash a presentation file.

## Typed batch allowlist

`slides.batch_update` accepts only:

- slide and element creation: `createSlide`, `createShape`, `createTable`, `createImage`, `createSheetsChart`;
- text and style: `insertText`, `deleteText`, `updateTextStyle`, `updateParagraphStyle`;
- linked and image content: `refreshSheetsChart`, `replaceImage`;
- structure and ordering: `deleteObject`, `updateSlidesPosition`, `duplicateObject`;
- bounded property updates: `updatePageElementTransform`, `updateShapeProperties`, `updatePageProperties`, `updateTableCellProperties`;
- bounded replacement: `replaceAllText`.

There is no raw request or HTTP escape hatch. Unknown variants and nested fields fail before provider I/O. Batches are limited to 100 requests and 512 KiB. Text values are limited to 100 KiB.

Object IDs, table ranges, dimensions, transforms, field masks, and created-ID uniqueness are validated recursively. Broad `*` field masks and regex replacement are rejected.

Remote image URLs must be HTTPS and may not use userinfo, fragments, localhost/private-name conventions, tailnet names, or IP literals. Google performs the actual media fetch; DNS-level protection therefore also depends on Google's fetch behavior.

## Destructive changes

`deleteText`, `deleteObject`, `replaceAllText`, `updateSlidesPosition`, `replaceImage`, and `refreshSheetsChart` are content-destructive or structural.

The first call performs a read-only preflight and returns:

- current presentation revision;
- request kinds and hashed object/text/URL identifiers;
- bounded structural impact;
- an exact `confirmation_sha256` bound to the presentation ID, revision, and serialized request batch.

Execution requires the current `required_revision_id`, `confirm_destructive=true`, and that exact hash. The connector sends `writeControl.requiredRevisionId` and directly reads the presentation back afterward. It never blindly retries a write after the provider may have received it.

## Privacy and telemetry

Presentation IDs, page IDs, slide text, speaker notes, image bytes, thumbnail URLs, OAuth material, and provider error bodies are excluded from durable telemetry. Thumbnail content URLs are caller-only data, typically valid for about 30 minutes; they must not be persisted or shared.

Read responses are compact and bounded to the manifest response budget. Provider errors are mapped to redacted FCP errors.

## Authentication

The connector reuses `fcp-google-discovery` and accepts the same bearer or credential-reference configuration as the other Google Workspace connectors. Selected methods are compatible with the existing broad Drive scope; integration and OAuth readback are handled by the later wrapper bead.

## Offline verification

The verifier uses the retained Google Workspace development cache so completed connectors do not create another 20–30 GiB target directory:

```bash
CARGO_TARGET_DIR=/home/ubuntu/.cache/fcp-google-docs-bd-2oc12 \
  scripts/e2e/google_slides_connector_verification.sh
```

It runs manifest parity/hash checks, formatting, check, unit/integration/loopback tests, JSONL evidence validation, clippy, and the graduation gauntlet. Loopback fixtures do not contact Google or fetch external media.

Live presentation reads/writes require a separate approved acceptance bead.
