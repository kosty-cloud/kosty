# Kosty test suite

## Offline guarantee

Every test in this directory is **fully offline**. No test performs an STS call,
a live boto3/AWS API call, or any network I/O. The suite is designed to run with
no AWS credentials, no `~/.aws` profile, and no connectivity.

This is a hard rule, not a convention: Kosty scans production accounts read-only,
and its tests must never depend on (or accidentally reach) a real account.

## How responses are exercised without AWS: botocore Stubber

Where a test needs to drive a real check function through real boto3 response
parsing, it uses [`botocore.stub.Stubber`](https://botocore.amazonaws.com/v1/documentation/api/latest/reference/stubber.html).
Stubber queues canned responses (or client errors) on a real boto3 client and
validates every queued payload against the service's own API model, so a stubbed
response that does not match the real API shape fails the test.

### Why Stubber and not moto

`Stubber` ships inside **botocore**, which is already a dependency of boto3 — the
official AWS SDK. Using it adds **zero new runtime or test dependency**.

`moto` is a separate third-party package that re-implements AWS services. It is
widely used and capable, but adopting it would add a dependency to install,
pin, and keep in step with boto3. For Kosty's needs — parsing known response
shapes and permission errors through the check functions — Stubber covers the
cases without that extra surface. The suite therefore standardises on Stubber
and does **not** introduce moto.

## What is covered

Mechanisms (the engine, loader, config, reporter, storage plumbing):

- **Plugin loader trust boundary** — `test_loader.py` (manifest/SHA-256 integrity,
  strict vs. lenient loading, loader errors).
- **Engine error isolation and the global/regional split** — `test_engine_run_service.py`
  (a failing check is recorded in `ScanResult.errors` rather than swallowed,
  global checks run once across regions, `run` vs. `run_service` parity, check_id /
  finding_type / deep filtering, loader-error surfacing).
- **Registry** — `test_registry.py` (duplicate `check_id` handling).
- **Exclusions** — `test_config_exclusions.py` and `test_config_honoring.py`
  (ARN fnmatch, tag Key/key casings, account/region/service), plus
  `test_tag_utils.py` for tag normalisation.
- **Reporter and storage** — `test_reporter.py` and `test_cli_run_checks.py`
  (CSV injection sanitisation, the `.sha256` sidecar, save-to confinement to the
  working directory, and `s3://` routing at the StorageManager boundary).
- **Permission-error convention** — `test_error_utils.py` and
  `test_session_utils.py`.
- **Timeout seam** — `test_boto_session.py` (the `TimeoutClientSession` proxy
  injects the configured botocore `Config`, preserves a caller-supplied
  `config=`, is idempotent, and delegates non-client attributes).

Representative check samples (one per pattern), in `test_checks_stubber.py`:

- **Cost** — an orphaned EBS volume yields a `Finding` with positive
  `monthly_savings`.
- **Security** — a security group with SSH open to `0.0.0.0/0` yields a security
  `Finding`.
- **Permission denied** — a Bedrock `AccessDeniedException` is re-raised by
  `handle_check_error` and lands in `ScanResult.errors` (not swallowed).

## What is NOT covered

- **Not all 151 checks.** The suite tests the shared mechanisms plus one
  representative sample per pattern (cost, security, permission-denied). Adding
  a per-check Stubber test for every check is out of scope; checks share the same
  execution and error-handling paths, which the samples exercise.
- **No live AWS.** Nothing here contacts a real account, region, or endpoint.
- **The web dashboard JS is not part of this Python suite.** `dashboard/` is a
  single-file vanilla-JS page and is validated separately.

## How to run

From the repository root:

```bash
pytest                      # full suite
pytest tests/<file> -q      # a single file, e.g. pytest tests/test_boto_session.py -q
```

No credentials or network access are required.

## The offline rule for new tests

Every new test **must stay offline**. In practice:

- Construct `Finding` / `ScanResult` objects directly, or drive a check through
  `botocore.stub.Stubber`.
- Build a `ConfigManager` from a `kosty.yaml` written under `tmp_path`.
- Use a `MagicMock` where a boto3 `Session` is expected, and have its `.client`
  return a stubbed client when a real response shape is needed.
- **Never** reach for STS, a live boto3 call, or the network, and **never** add a
  new runtime dependency (no moto).
