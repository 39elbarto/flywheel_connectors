# Google Forms Connector

Status: **INCUBATING**. This bead validates the connector offline; live Google access remains a separate acceptance gate.

## Scope

The connector exposes six typed operations:

| Operation | Capability | Safety | Purpose |
|---|---|---|---|
| `forms.get` | `forms.read` | Safe | Read form info, settings, publishing state, and a bounded item page. |
| `forms.create` | `form.structure.write` | Risky | Create one form and read it back. |
| `forms.batch_update` | `form.structure.write` | Dangerous | Apply an allowlisted, revision-guarded batch. |
| `forms.responses.get` | `forms.responses.read` | Safe | Read one private response. |
| `forms.responses.list` | `forms.responses.read` | Safe | Read a bounded response page with an optional timestamp filter. |
| `forms.set_publish_settings` | `form.publish.write` | Dangerous | Explicitly publish/unpublish and accept/stop responses. |

Drive remains responsible for the file title, sharing, folder placement, quarantine, restoration, and lifecycle. This connector cannot delete or trash a form file. Pub/Sub watches are intentionally excluded.

## Structure writes

`forms.batch_update` accepts only the six official request families: `updateFormInfo`, `updateSettings`, `createItem`, `moveItem`, `deleteItem`, and `updateItem`. Item, question, grading, ordering, image, and video structures are recursively allowlisted; unknown nested fields fail before provider I/O. There is no raw JSON or HTTP escape hatch.

The API can read existing file-upload questions but does not support creating them. The connector therefore rejects file-upload question writes instead of producing a provider-side surprise.

Deleting/moving items, clearing quiz grading by turning quiz mode off, and replacing grading are destructive. They first return a confirmation receipt bound to the exact form ID, current revision, and typed request batch. Execution requires that revision and hash. All batches are capped at 100 requests and 512 KiB.

## Publishing

Publishing changes always use a two-step confirmation. The receipt binds the desired state to both the current form revision and a hash of the current publish settings. The connector then performs a direct readback. Legacy forms without `publishSettings` are reported as unsupported.

## Responses and privacy

List filters accept only Google's `timestamp > RFC3339Z` and `timestamp >= RFC3339Z` forms. Pages are capped at 100 responses. Continuation tokens are returned with a binding hash and cannot be reused with another form or filter.

Answers, respondent emails, file-upload references, response IDs, page tokens, OAuth material, and provider error bodies are caller-only. They must not appear in durable telemetry, verifier evidence, or logs. Caller payloads are bounded to the FCP datagram budget.

## Offline verification

The verifier reuses the retained Google Workspace target directory:

```bash
CARGO_TARGET_DIR=/home/ubuntu/.cache/fcp-google-docs-bd-2oc12 \
  scripts/e2e/google_forms_connector_verification.sh
```

It performs manifest, format, check, unit/integration, loopback, JSONL privacy, clippy, and graduation checks without contacting Google.
