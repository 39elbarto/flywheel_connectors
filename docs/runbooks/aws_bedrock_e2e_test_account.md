# AWS Bedrock E2E Test Account

Bead: `flywheel_connectors-4kw5f.2.9.2.13.1`

## Purpose

Live AWS Bedrock proof must run against a sealed test account, not a personal or production AWS account. Replay mode remains the default for CI and routine local verification.

## Account Setup

1. Create or select a disposable AWS account dedicated to FCP Bedrock verification.
2. Enable Bedrock model access in `us-east-1` for `anthropic.claude-3-haiku-20240307-v1:0`.
3. Create an IAM user or role scoped to the minimum live smoke policy.
4. Configure monthly cost alerts at 1 USD and 10 USD.
5. Store credentials only in the operator credential-injection path. Do not commit credentials, profiles, or generated logs containing raw credential material.

Minimum IAM policy shape:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream",
        "bedrock:ListFoundationModels"
      ],
      "Resource": "*"
    }
  ]
}
```

Narrow `Resource` to the selected model ARN once the account-specific ARN is known.

## Replay Verification

Replay mode never calls AWS:

```bash
OUT_ROOT=/tmp/fcp-aws-bedrock-replay \
scripts/e2e/aws_bedrock_connector_verification.sh --mode replay
```

Expected live status in replay mode: `skipped`, with a schema-versioned JSONL skip record.

## Live Verification

Run live mode only after confirming the account and cost alert:

```bash
AWS_BEDROCK_ACCESS_KEY_ID=... \
AWS_BEDROCK_SECRET_ACCESS_KEY=... \
AWS_BEDROCK_REGION=us-east-1 \
AWS_BEDROCK_MODEL_ID=anthropic.claude-3-haiku-20240307-v1:0 \
OUT_ROOT=/tmp/fcp-aws-bedrock-live \
scripts/e2e/aws_bedrock_connector_verification.sh --mode live
```

Optional streaming proof:

```bash
AWS_BEDROCK_STREAM_E2E=1 scripts/e2e/aws_bedrock_connector_verification.sh --mode live
```

## Evidence Expectations

The artifact root must contain:

- `summary.json`
- `environment.json`
- `evidence/fixture_boundary.jsonl`
- `evidence/live_smoke.jsonl`
- `logs/*.log`
- `replay.sh`

JSON and JSONL evidence must include `schema_version: "1.0.0"` and must not include prompts, completions, AWS access keys, secret keys, session tokens, bearer tokens, or full SigV4 signatures.

## Recovery

- If live mode reports missing variables, set the four required `AWS_BEDROCK_*` variables and rerun.
- If Bedrock returns authorization errors, verify model access is enabled in the selected region and the IAM policy covers the model.
- If replay mode fails before Cargo, inspect the generated log path in `summary.json`; classify wrapper failures separately from connector failures.
- If live mode spends unexpected quota, disable the IAM user or role, inspect CloudWatch/Cost Explorer, and rotate the test credential before rerunning.
