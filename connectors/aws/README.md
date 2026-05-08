# AWS Connector V3 Contract

> **Status**: runtime contract documented; live parser gaps documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: `scripts/e2e/aws_connector_verification.sh`
> **Primary upstream**: https://docs.aws.amazon.com/AmazonS3/latest/API/Type_API_Reference.html
> **EC2 upstream**: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html
> **Lambda upstream**: https://docs.aws.amazon.com/lambda/latest/api/API_Invoke.html
> **STS upstream**: https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html
> **Signing upstream**: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html

## Purpose

This document fixes the operator-facing contract for `fcp.aws`. The connector exposes the AWS surface implemented in this crate: S3 bucket/object operations, EC2 instance read and lifecycle operations, Lambda list/invoke, STS identity, and credential health.

The connector is intentionally a work-zone AWS operations bridge. It is not a general AWS SDK, CloudFormation orchestrator, IAM policy editor, credential broker, inventory warehouse, event listener, or production-safe live mutation harness.

## Current Runtime Snapshot

The current runtime exposes these operations:

- `aws.s3.list_buckets`
- `aws.s3.list_objects`
- `aws.s3.get_object`
- `aws.s3.put_object`
- `aws.s3.delete_object`
- `aws.ec2.describe_instances`
- `aws.ec2.start_instance`
- `aws.ec2.stop_instance`
- `aws.ec2.terminate_instance`
- `aws.lambda.list_functions`
- `aws.lambda.invoke`
- `aws.sts.get_caller_identity`
- `aws.health`

Important runtime truths the contract preserves:

- Configuration requires `region`, `access_key_id`, and `secret_access_key`.
- `session_token` is optional and is forwarded as `X-Amz-Security-Token` when present.
- Credential values are trimmed on configuration and redacted in debug output.
- Default service endpoints are region-derived for S3, EC2, and Lambda, and global for STS:
  - `https://s3.{region}.amazonaws.com`
  - `https://ec2.{region}.amazonaws.com`
  - `https://lambda.{region}.amazonaws.com`
  - `https://sts.amazonaws.com`
- `s3_base_url`, `ec2_base_url`, `lambda_base_url`, and `sts_base_url` overrides are accepted for staging, LocalStack, signing proxies, and deterministic tests.
- Endpoint overrides must be valid URLs, must not include userinfo/query/fragment, and must use HTTPS unless they target loopback verification hosts.
- Runtime request timeout defaults to `30_000 ms`.
- The client signs requests with SigV4 and sets `Authorization`, `X-Amz-Date`, and `X-Amz-Content-Sha256`.
- The connector uses the shared HTTP retry loop for provider dispatch.
- Retryable classes include request timeout/connect errors, HTTP 429, HTTP 503, and 500-class API errors.
- 401 and 403 map to unauthorized; 404 maps to not found; other non-success non-500 statuses map to terminal API errors.
- Handshake grants requested capabilities and installs a bound `CapabilityVerifier`.
- `invoke` and `simulate` both verify bound capability tokens against the requested operation.
- `self_check` intentionally abstains against default STS to avoid probing production AWS credentials during routine readiness checks.
- `self_check` runs only when `sts_base_url` points at a custom verification endpoint.
- `health` is local readiness plus provisioning detail; it does not call AWS directly.
- `introspect` exposes no streaming support.

## Manifest And Live-Parser Drift In This Checkout

The runtime, manifest, and live AWS protocol state are not fully aligned in this checkout:

- `manifest.toml` still says deterministic verification relies on endpoint overrides "until SigV4 signing is implemented"; current client code does implement SigV4.
- `operator_guidance()` has one stale prerequisite string with the same "before SigV4 signing exists" wording; the doctor check correctly reports SigV4 as active.
- The connector signs real AWS request shapes, but most response parsers expect connector-normalized JSON fixture payloads:
  - S3 bucket/object list and mutation helpers call REST endpoints but deserialize JSON fixtures.
  - EC2 and STS use AWS Query API request shapes but deserialize JSON fixtures instead of native XML responses.
  - Lambda list/invoke use Lambda API paths but deserialize the connector's simplified JSON response types.
- Routine deterministic tests therefore prove signed dispatch, capability enforcement, risky-operation metadata, error mapping, and lifecycle behavior against WireMock fixtures, not full native AWS response-envelope parity.

A follow-up parser parity bead should reconcile S3 XML, EC2 Query XML, STS Query XML, and Lambda native response envelopes before this connector is described as live AWS complete.

## First-Slice Scope

The first AWS README slice documents the existing runtime surface:

- S3 bucket listing through `GET /`
- S3 object listing through `GET /{bucket}?list-type=2`
- S3 object download through `GET /{bucket}/{key}`
- S3 object upload through `PUT /{bucket}/{key}`
- S3 object deletion through `DELETE /{bucket}/{key}`
- EC2 instance listing through `Action=DescribeInstances&Version=2016-11-15`
- EC2 start, stop, and terminate through AWS Query API action calls
- Lambda function listing through `GET /2015-03-31/functions`
- Lambda invocation through `POST /2015-03-31/functions/{function_name}/invocations`
- STS identity through `Action=GetCallerIdentity&Version=2011-06-15`
- SigV4 static-key and session-token signing
- endpoint override, lifecycle, doctor, self-check, introspection, simulation, and shutdown surfaces

## Auth And Scope Boundary

- Authentication mechanism: static AWS access key and secret access key, with optional session token.
- Home zone: `z:work`.
- Allowed source zones: `z:work` and `z:private`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Capability surface:
  - `aws.s3.read` gates S3 bucket listing, object listing, and object download.
  - `aws.s3.write` gates S3 object upload and deletion.
  - `aws.ec2.read` gates EC2 instance listing.
  - `aws.ec2.write` gates EC2 start, stop, and terminate.
  - `aws.lambda.read` gates Lambda function listing.
  - `aws.lambda.write` gates Lambda invocation.
  - `aws.iam.read` gates STS identity and AWS health.
- The connector does not persist credentials, account IDs, ARNs, bucket names, object bodies, instance IDs, Lambda names, or provider responses beyond process memory.
- The manifest required capability list covers network primitives; operation entries and runtime introspection carry the operation-specific `aws.*` capability IDs.

## Network And Runtime Invariants

- Production hosts are under `*.amazonaws.com`, with `s3.amazonaws.com`, `ec2.amazonaws.com`, `lambda.amazonaws.com`, and `sts.amazonaws.com` called out by operation constraints.
- Production port: `443`.
- TLS and SNI are required for live provider traffic.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Runtime loopback endpoint overrides are test-only.
- Runtime request timeout: `30_000 ms`.
- Manifest `aws.s3.get_object` total timeout is `120_000 ms`; other operations use `30_000 ms`.
- Maximum response bytes are `104_857_600` for S3 get object, `10_485_760` for list/read paths, and `1_048_576` for mutation responses.
- Sandbox profile is `strict`, with `128 MB` memory, `25%` CPU, `30_000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not open listeners and does not implement FCP subscriptions.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `aws.s3.read` | List buckets, list objects, and download object bodies. |
| `aws.s3.write` | Upload and delete S3 objects. |
| `aws.ec2.read` | List EC2 instances visible to the credentials. |
| `aws.ec2.write` | Start, stop, and terminate EC2 instances. |
| `aws.lambda.read` | List Lambda functions. |
| `aws.lambda.write` | Invoke Lambda functions. |
| `aws.iam.read` | Read STS caller identity and credential-health status. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `aws.s3.list_buckets` | `GET /` | `aws.s3.read` | `Safe` | `Low` | `None` | Reads bucket inventory for the current account. |
| `aws.s3.list_objects` | `GET /{bucket}?list-type=2` | `aws.s3.read` | `Safe` | `Low` | `None` | Reads object keys and metadata in one bucket. |
| `aws.s3.get_object` | `GET /{bucket}/{key}` | `aws.s3.read` | `Safe` | `Low` | `None` | Downloads one object body and response metadata. |
| `aws.s3.put_object` | `PUT /{bucket}/{key}` | `aws.s3.write` | `Risky` | `Medium` | `Strict` | Creates or overwrites object content. |
| `aws.s3.delete_object` | `DELETE /{bucket}/{key}` | `aws.s3.write` | `Dangerous` | `High` | `Strict` | Deletes object content and may be irreversible without versioning. |
| `aws.ec2.describe_instances` | `Action=DescribeInstances` | `aws.ec2.read` | `Safe` | `Low` | `None` | Reads instance inventory. |
| `aws.ec2.start_instance` | `Action=StartInstances` | `aws.ec2.write` | `Risky` | `Medium` | `Strict` | Starts a stopped instance and can incur compute cost. |
| `aws.ec2.stop_instance` | `Action=StopInstances` | `aws.ec2.write` | `Risky` | `Medium` | `Strict` | Stops a running instance and can interrupt workloads. |
| `aws.ec2.terminate_instance` | `Action=TerminateInstances` | `aws.ec2.write` | `Dangerous` | `Critical` | `Strict` | Terminates an instance and can permanently destroy attached state. |
| `aws.lambda.list_functions` | `GET /2015-03-31/functions` | `aws.lambda.read` | `Safe` | `Low` | `None` | Reads Lambda function inventory. |
| `aws.lambda.invoke` | `POST /2015-03-31/functions/{function_name}/invocations` | `aws.lambda.write` | `Risky` | `Medium` | `BestEffort` | Executes provider code with caller-supplied payload. |
| `aws.sts.get_caller_identity` | `Action=GetCallerIdentity` | `aws.iam.read` | `Safe` | `Low` | `None` | Reads identity for the configured credentials. |
| `aws.health` | STS identity probe | `aws.iam.read` | `Safe` | `Low` | `Strict` | Confirms custom STS verification endpoint authentication. |

## Explicit Non-Goals

The current implementation does not include:

- IAM role assumption, profile discovery, SSO, IMDS, or automatic credential refresh
- AWS SDK integration or complete native response-envelope parsing
- CloudFormation, CloudWatch, EventBridge, SNS, SQS, DynamoDB, IAM, KMS, RDS, ECS, EKS, or broader AWS APIs
- S3 multipart upload, range reads, object version selection, bucket creation/deletion, or ACL/policy management
- EC2 reboot, run instances, volume/snapshot mutation, security group mutation, or termination-protection controls
- Lambda function creation, update, deletion, logs, aliases, layers, event sources, or async result tracking
- durable inventory storage, local cache, or account-wide scanner state
- public-zone invocation or inbound callback listeners
- connector-local credential vaulting

These are excluded on purpose:

- The useful first slice is bounded S3/EC2/Lambda/STS operations with clear capability gates.
- S3 delete, EC2 stop, EC2 terminate, Lambda invoke, and S3 put can mutate production state and need dedicated staging resources for proof.
- Full AWS service coverage belongs in separate beads with service-specific auth, parser, and safety contracts.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configuration, handshake state, runtime readiness, request counters, and error counters
- auth mode as static keys or static keys with session token
- endpoint override status for S3, EC2, Lambda, and STS
- SigV4 active status
- custom STS self-check target status
- manifest hash, verification script, artifact root, rerun commands, and operator guidance
- operation metadata, schemas, capability IDs, risk levels, safety tiers, idempotency, and approval modes
- simulation denial for missing readiness, missing handshake, unknown operations, or invalid bound capability tokens

The deterministic integration evidence is anchored on WireMock and connector-local tests covering:

- lifecycle health, doctor, self-check, introspection, and shutdown
- SigV4 header construction and redaction
- custom endpoint overrides
- S3 delete, EC2 terminate, Lambda list, and STS identity dispatch
- risky and dangerous operation metadata
- bound capability-token verification
- input-required validation paths
- default endpoint health behavior and custom STS readiness
- retryable and terminal provider error mapping

## Source Notes

- `connectors/aws/src/connector.rs` defines configuration parsing, lifecycle handlers, capability mapping, doctor/self-check details, simulation, operation dispatch, and introspection metadata.
- `connectors/aws/src/client.rs` defines endpoint selection, SigV4 signing, HTTP retry dispatch, S3/EC2/Lambda/STS request builders, response parsing, and provider error mapping.
- `connectors/aws/src/types.rs` defines credentials and normalized S3, EC2, Lambda, STS, and health response types.
- `connectors/aws/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, and operation AI hints.
- `connectors/aws/tests/integration.rs` covers deterministic WireMock operation behavior, SigV4 headers, lifecycle diagnostics, capability verification, and metadata evidence.

## Verification Bundle

The tracked verification bundle is `scripts/e2e/aws_connector_verification.sh`.

The verification surface captures:

- runtime operation contract tests
- deterministic WireMock AWS API coverage
- auth redaction, endpoint override, lifecycle, doctor, self-check, risky mutation, dangerous operation, and introspection tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use disposable AWS credentials scoped to the exact read and mutation operations under test.
- Use a staging AWS account, LocalStack stack, or signing proxy for routine proof.
- Configure `sts_base_url` to a custom verification endpoint when expecting `self_check` to run.
- Keep S3 buckets, EC2 instances, and Lambda functions synthetic for live verification.

**Dedicated environment**:

- Use staging-only buckets, objects, instances, Lambda functions, and STS endpoints.
- Never run S3 delete or EC2 terminate against production resources during verification.
- Do not use operator personal credentials for automated mutation tests.
- Treat account IDs, ARNs, bucket names, instance IDs, function names, object keys, and non-public endpoint override URLs as sensitive.

**Redaction rules**:

- Redact `access_key_id`, `secret_access_key`, `session_token`, `Authorization`, `X-Amz-Security-Token`, and full signed URL/query material.
- Redact object bodies, object keys when sensitive, account IDs, ARNs, instance IDs, function names, provider payloads, and provider error bodies.
- Verification output should use operation names, endpoint classes, status/error classes, result counts, and redacted identity/account markers.

**Common remediation**:

- If configuration fails, check `region`, `access_key_id`, `secret_access_key`, and endpoint override URL policy.
- If `doctor` reports missing endpoint overrides, decide whether the run is a live AWS run or a deterministic stub run.
- If `self_check` degrades with `self_check_unsupported_on_default_sts`, set `sts_base_url` to a verification endpoint.
- If AWS reports `SignatureDoesNotMatch`, check system clock skew, region, service name, host, path, query, and payload hash.
- If `invoke` returns a capability error, ensure the bound token capability and operation list match the requested operation.
- If live AWS calls succeed at the HTTP layer but parsing fails, treat it as the known native response parser gap and route the fix through a parser parity bead.

**Rerun commands**:

- `scripts/e2e/aws_connector_verification.sh`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-aws-e2e cargo check -p fcp-aws --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-aws-e2e cargo test -p fcp-aws --test integration -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-aws-e2e cargo clippy -p fcp-aws --all-targets --no-deps -- -D warnings`
- `ubs connectors/aws/README.md`
