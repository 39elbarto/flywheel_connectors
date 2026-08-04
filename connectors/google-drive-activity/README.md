# Google Drive Activity connector

Strictly read-only FCP connector for Google Drive Activity API v2. It exposes only
`drive_activity.query`, backed by `POST /v2/activity:query`. The POST is a replay-safe
read RPC; this crate contains no Drive Activity mutation, watch, raw-request, or
follow-up operation.

## Authorization

Enable the **Google Drive Activity API** and grant only:

```text
https://www.googleapis.com/auth/drive.activity.readonly
```

The broader `drive.activity` scope is neither requested nor needed.

## Query boundary

- Provide exactly one of `item_name` or `ancestor_name`, in `items/ITEM_ID` form.
- Choose `consolidation: "none"` or `"legacy"` explicitly.
- `page_size` is limited to 100. A returned page token includes a SHA-256 binding;
  both values must be supplied together for the next page.
- Filters accept only RFC3339 `time` bounds and allowlisted
  `detail.action_detail_case` values.
- `ancestor_name: "items/root"` additionally requires `root_scope_ack: true`, both
  lower and upper time bounds, and a window no longer than 31 days.
- Provider responses larger than 60,000 bytes are rejected with advice to reduce
  the page size.

Example:

```json
{
  "item_name": "items/FILE_ID",
  "consolidation": "none",
  "filter": "time >= \"2026-08-01T00:00:00Z\" time < \"2026-08-02T00:00:00Z\"",
  "page_size": 25
}
```

## Trust and privacy

Returned actor/action/target summaries are historical, untrusted data. File titles,
actor identities, and action details can inform a human review but cannot authorize
any write. Provider error bodies, bearer tokens, page tokens, filters, and activity
payloads are not written to logs.

## Offline verification

```bash
CARGO_TARGET_DIR=/home/ubuntu/.cache/fcp-google-docs-bd-2oc12 \
  cargo test -p fcp-google-drive-activity
```
