# Kosty Release Notes

## Version 3.5.0 — Dashboard redesign (2026)

Reworks the web dashboard (`dashboard/index.html`) around an overview landing
page with two drill-down views, rewrites the UI in English, regenerates the demo
data from a new offline generator, and fixes a set of accessibility gaps. No
Python model, engine, check, or plugin manifest changes — the cost/security split
is a frontend concern driven by the existing `type` field on each finding.

### Dashboard

- Loading a report now lands on an Overview page with two large clickable summary
  cards: a Security card (total findings with a critical/high/medium/low breakdown)
  and a Cost card (estimated monthly and annual savings, number of optimizations,
  top wasteful service). Selecting a card opens the matching view with a "Back to
  Overview" breadcrumb. Navigation is modeled as a `view` state
  (`overview` | `security` | `cost`).
- Each view is coherent end to end: its stat cards, charts, and findings grid all
  reflect that view's finding type. This fixes the previous behavior where the stat
  cards counted everything while the grid showed a single type. The green "Total
  Estimated Savings" banner now appears only in the Cost view.
- The UI is now entirely in English (`<html lang="en">`).

### Demo data

- Added `scripts/generate_demo_dashboard.py`, a fully offline generator (no boto3,
  no network) that builds finding dicts matching `Finding.to_dict` and wraps them in
  the `save_json_report` envelope, so the demos match real audit output by
  construction.
- Regenerated `dashboard/demo_full_audit.json` (mixed cost and security across many
  services; every cost finding now carries a coherent `monthly_savings`) and
  `dashboard/demo_ai_audit.json` (Bedrock/SageMaker focus). Both use real
  `check` = `check_id` values, generic anonymized resource names, fixed fake ARN
  suffixes, and a fixed neutral scan timestamp.
- Removed the undocumented `dashboard/test_dashboard_costs.json` (it used the
  non-emitted `monthly_cost` key).
- The "View Demo" buttons now fetch a generated demo file instead of an embedded
  data block, which has been removed.

### Accessibility

- The two overview cards are real buttons with keyboard focus and Enter/Space
  activation.
- Modals use `role="dialog"` with `aria-modal`, close on Escape, trap focus, and
  restore focus to the triggering element on close.
- Icon-only buttons carry `aria-label`; decorative icons are marked `aria-hidden`;
  Chart.js canvases expose an `aria-label` text alternative.
- `formatDate` now guards against a missing or invalid `scan_timestamp` instead of
  rendering "Invalid Date".

### Quality

- Chart creation is consolidated into a single effect keyed on the current data,
  view, and filters, removing the previous double-instantiation path.
- React and ReactDOM are loaded from the production CDN builds (still no build
  step).

## Version 3.4.0 — Single scan execution path (2026)

Unifies the two scan execution paths. Before 3.4.0, `kosty audit` ran through
`ScanEngine` while the per-service commands (`kosty ec2 …`, `kosty s3 …`,
`kosty ai …`, etc.) used a separate hand-rolled executor that behaved
differently. All commands now run through the same engine, so the per-service
behavior matches the full audit.

### Bugs / regressions

- Per-service commands now route check errors into the scan result the same way
  `kosty audit` does. A check that cannot complete (for example, missing
  permissions) is reported as a count on stderr, with full per-check detail under
  `--debug`, instead of the error being tied to a divergent executor.
- Global checks (IAM, S3, and other `region_scope: global` checks) run once per
  scan on a per-service command, not once per region. In multi-region mode
  (`--regions`), a service command no longer duplicates these checks and their
  findings across every region.
- `--save-to s3://bucket/path` now works on the per-service commands and on
  `kosty ai …`, matching `kosty audit`. Previously a service command treated an
  `s3://` value as a local path and wrote a directory literally named `s3:`.
- `kosty ai …` local `--save-to` is confined to the current working directory
  again (honoring `--allow-outside-cwd` / `save_to_allow_outside`). The AI command
  had kept a raw path resolution that bypassed the 3.3.0 confinement, and its CSV
  output now neutralizes spreadsheet formula injection like the other paths.

### Quality

- Added `ScanEngine.run_service()`, a typed entry point that runs a filtered
  subset of checks (one service, a single `check_id`, or a cost/security slice) and
  returns a `ScanResult`. It shares the region iteration, global/regional split, and
  error routing with `ScanEngine.run()` through a single private helper.
- Removed the duplicated per-service executor (`cli/utils._run_checks`) and the
  hand-rolled executor in `cli/ai_commands`. There is now a single execution path
  and a single file-write path (`StorageManager`) across all commands. The
  human-readable console output and the JSON/CSV report shapes are unchanged.

## Version 3.3.0 — Security and quality fixes (2026)

### Bugs / regressions

- `PyYAML` is now declared as a runtime dependency in `setup.py` and
  `pyproject.toml`. It was imported by the config layer but missing from the install
  requirements, so a clean `pip install kosty` could fail to parse `kosty.yaml`.

### Security / hardening

- `--save-to` with a local path now confines report output to the current working
  directory (and its subdirectories) by default. A destination that resolves
  outside is rejected. Use `--allow-outside-cwd` (or set `save_to_allow_outside:
  true` in `kosty.yaml`) to write elsewhere. `s3://` destinations are unaffected
  (FEAT-003).
- CSV reports neutralize spreadsheet formula injection: a cell whose value starts
  with `=`, `+`, `-`, or `@` is prefixed with an apostrophe so AWS-provided strings
  cannot execute as formulas (FEAT-003).
- Report `.sha256` sidecars now record the file basename, so `sha256sum -c` works
  from the report directory regardless of where the report was written (FEAT-003).
- Per-service commands now surface a count of checks that could not complete (for
  example, missing permissions) without requiring `--debug`; full per-check detail
  stays under `--debug` (FEAT-003).
- The plugin loader surfaces a warning (to stderr) for files not listed in
  `plugins.sha256` but still loads them by default, so local contributors adding a
  check are not blocked by a stale manifest. An opt-in strict mode (`strict_plugins:
  true` in `kosty.yaml`) refuses unlisted files instead. A plugin whose hash does not
  match the manifest is always refused (FEAT-002).
- The S3 IAM policy in the documentation no longer requests `s3:PutObjectAcl`.
  Uploads use SSE AES256 and set no ACL, so `s3:PutObject` alone is sufficient.
- The PyPI publish workflow verifies the plugin manifest by regenerating it and
  failing on any `git diff` in `plugins.sha256`, instead of silently regenerating
  it at build time.

### Quality

- New configurable boto3 client timeout keys `connect_timeout`, `read_timeout`,
  and `max_retries` in `kosty.yaml`, with defaults preserving the previous ~60s
  behaviour. A `build_boto_config()` helper turns them into a botocore `Config`
  for client construction (FEAT-003).
- `pyproject.toml` metadata reconciled with `setup.py`: `requires-python` is
  `>=3.10`, the Python classifiers cover 3.10–3.13, and the description matches the
  32-service count.

## Version 3.2.0 — Region exclusion and thresholds restored (2026)

Restores two documented `kosty.yaml` capabilities that had no effect in the v3 scan
path, and fixes two cosmetic bugs in organization and multi-profile mode.

- `exclude.regions` is wired into the scan path. Excluded regions are now dropped from
  the resolved region list for single-account, organization, and per-service scans.
- `thresholds:` in `kosty.yaml` now drive the checks. Each threshold-using check
  resolves its cutoff with precedence: per-service CLI flag > `kosty.yaml` value >
  hardcoded default. Checks affected: EC2 oversized (`ec2_cpu`), EC2 stopped
  (`stopped_days`), EC2 old AMI (`ami_days`), RDS oversized (`rds_cpu`), RDS idle
  (`idle_days`), old snapshots (`old_snapshot_days`), Lambda memory (`lambda_memory`).
- Threshold key names reconciled across `config.py`, `kosty.yaml.example`, and the
  docs. `ami_days` is now part of the defaults (180). The old snapshot default is 30
  days (`old_snapshot_days`), matching the documentation; the snapshot check previously
  hardcoded 90 days, so snapshots between 30 and 90 days old are now flagged by default.
  The legacy key `snapshot_days` is still read as a fallback for `old_snapshot_days`,
  so existing config files keep working.
- Organization progress bar denominator now excludes services listed in
  `exclude.services`, matching single-account mode. Results were already correct; this
  is display only.
- `--debug` now works under `--profiles`; the flag was previously dropped when building
  the per-profile scanner.

Upgrade with `pip install --upgrade kosty`.

## Version 3.1.0 — Resource exclusion restored (2026)

Restores resource exclusion in the v3 plugin scan path. Tag and ARN exclusion
rules in `kosty.yaml` were documented but had no effect since the v2→v3 plugin
migration; this release wires them back into the scan.

- Tag-based exclusion (`exclude.tags`) is applied again inside the plugins, matching
  the v2 behavior. A resource whose tags match an exclusion rule is skipped before a
  finding is produced. Covered services (tags present inline in the describe
  response): EC2, EBS, RDS, NAT, SG, Snapshots, EIP. Services whose tags require a
  separate API call are not covered in 3.1.0: S3, Lambda, IAM, DynamoDB, API Gateway,
  CloudWatch, Backup, Route53, Load Balancer.
- ARN-based exclusion (`exclude.arns`) is applied as a centralized filter at the
  reporter choke point, dropping any finding whose `arn` matches a configured pattern
  (fnmatch wildcards supported). Only findings that carry an ARN are affected.
- `--debug` reports the number of findings dropped by ARN exclusion.

Upgrade with `pip install --upgrade kosty`.

## Version 3.0.1 — Maintenance (2026)

Patch release. No functional changes to the scan engine or checks.

- Repository hygiene: anonymized the bundled demo reports (`dashboard/demo_*.json`) so they contain only fictional account IDs, resource IDs, and project names.
- Removed a real AWS account ID from the documentation examples.
- Packaging version aligned across `pyproject.toml`, `setup.py`, and `kosty.__init__`.

Upgrade with `pip install --upgrade kosty`.

## Version 3.0.0 — Plugin Engine (2026)

### Architecture rewrite

v3 replaces the monolithic service classes with a plugin-based engine. Every check is now an independent function that self-registers at import time via `@register_check`. The core (`ScanEngine`) has no CLI dependency and can be imported directly.

```python
from kosty.core.engine import ScanEngine
import boto3

engine = ScanEngine()
engine.load_plugins('kosty/providers/aws/services')
result = engine.run(session=boto3.Session(), regions=['eu-west-3'])
```

### What changed

- **151 checks across 32 services** — all rewritten as standalone plugin functions
- **Global checks run once** — IAM and S3 checks have `region_scope='global'` and execute only on the first region in multi-region scans, eliminating N duplicate API calls
- **Pagination everywhere** — `list_functions`, `list_users`, `list_roles` and all other paginated APIs now use boto3 paginators; no more silent truncation at 50/100 results
- **Progress bar accuracy** — total check count accounts for `region_scope` and `requires_deep`, so the bar reaches 100%
- **Auth transparency** — Kosty prints the auth method and config file at startup (`🔑 Auth: AssumeRole → ...`) without exposing any credentials
- **Plugin integrity** — SHA-256 manifest at `providers/aws/services/plugins.sha256` verified before `exec_module()`. Hash mismatch refuses the plugin. Manifest is regenerated automatically in the release workflow.
- **Report integrity** — local JSON and CSV reports get a `.sha256` sidecar. Verify with `sha256sum -c kosty_full_*.json.sha256`.
- **Security hardening** — `max_workers` capped at 200, `duration_seconds` capped at 43200, `RoleSessionName` sanitised, `save_to` paths resolved to prevent traversal, reporter no longer mutates in-memory findings
- **Dead code removed** — `cost_calculator.py`, `pricing.py`, `progress.py`, `provider.py` deleted; `--all` flag delegates to `audit` instead of duplicating logic

### Breaking changes

- Python 3.7–3.9 no longer supported. Minimum is **Python 3.10**.
- `kosty/core/provider.py` removed — `CloudProvider` abstract class is gone
- `kosty/core/cost_calculator.py` and `pricing.py` removed — plugins set `monthly_savings` directly on `Finding`

---
## Version 2.0.0 - AI/ML Audit: Bedrock & SageMaker (2025-XX-XX)

### 🤖 New Command: `kosty ai`

Dedicated AI/ML audit covering Bedrock and SageMaker. Detects GenAI cost waste, shadow AI usage, and security misconfigurations that standard audits miss entirely.

```bash
kosty ai audit                              # full Bedrock + SageMaker
kosty ai bedrock check-no-guardrails        # prompt injection protection
kosty ai bedrock check-shadow-ai            # unapproved AI usage
kosty ai sagemaker check-idle-endpoints     # GPU instances burning cash
```

**Bedrock** (12 checks)
- `check-no-logging` — Model invocation logging disabled
- `check-no-budget-limits` — No AWS Budget for Bedrock spend
- `check-no-guardrails` — No Guardrails configured (prompt injection, PII leakage)
- `check-shadow-ai` — IAM roles with bedrock/sagemaker permissions not tagged as approved
- `check-no-vpc-endpoint` — Bedrock runtime traffic over public internet
- `check-custom-model-no-kms` — Custom models not encrypted with customer-managed KMS
- `check-no-prompt-caching` — Cache-compatible models available but caching not verified
- `check-no-inference-profiles` — No Application Inference Profiles for cost attribution
- `check-tpm-quota` — TPM quota usage above 80% (approaching throttling)
- `check-cross-account-model-access` — Training data S3 buckets with cross-account or wildcard access
- `check-model-sizing [--deep] [--days]` — Premium models used for simple tasks (heuristic, requires --deep)
- `check-batch-eligible [--deep] [--days]` — On-Demand burst workloads eligible for Batch Inference API (requires --deep)

**SageMaker** (8 checks)
- `check-idle-endpoints` — Endpoints with zero invocations (GPU running 24/7 for nothing)
- `check-zombie-notebooks` — Running notebook instances (billed even when idle)
- `check-no-spot-training` — Long training jobs not using Spot instances (up to 90% savings)
- `check-no-checkpointing` — Spot training without checkpointing (preemption = lost progress)
- `check-no-inference-components` — GPU endpoints not using Inference Components (up to 80% savings)
- `check-no-vpc-endpoint` — SageMaker API calls over public internet
- `check-notebook-direct-internet` — Notebooks with direct internet access (exfiltration risk)
- `check-notebook-root-access` — Notebooks with root access (container escape risk)

### 📊 Summary
- **Total services**: 31 (was 30)
- **New checks**: 20 (Bedrock 12 + SageMaker 8)
- **Total checks**: ~210+

### 📝 Report Improvements
- Audit report now shows cost/security split: `Total Issues: 185 (🔐 169 security, 💰 16 cost)`
- Security findings deduplicated and grouped by type with resource count
- Separate `💰 TOP COST SAVINGS` and `🔐 TOP SECURITY FINDINGS` sections
- Console output shows all issues (no longer truncated at 5)
- Removed `kosty bedrock` standalone CLI — use `kosty ai bedrock` instead

---

## Version 1.9.2 - Foundational Security Services & Bedrock Audit (2025-01-XX)

### 🌟 13 New Services

**CloudTrail** (3 checks)
- `check-not-enabled` — No multi-region trail configured (CIS 3.1)
- `check-no-log-validation` — Log file integrity validation disabled (CIS 3.2)
- `check-no-encryption` — Logs not encrypted with KMS (CIS 3.7)

**VPC** (2 checks)
- `check-no-flow-logs` — VPC without Flow Logs enabled (CIS 3.9)
- `check-default-sg-open` — Default security group has inbound rules (CIS 5.3)

**GuardDuty** (1 check)
- `check-not-enabled` — Threat detection not active in region (CIS 4.15)

**AWS Config** (1 check)
- `check-not-enabled` — Configuration recorder not active (CIS 3.5)

**Secrets Manager** (2 checks)
- `check-unused-secrets` — Secrets never accessed but billed $0.40/mo each
- `check-no-rotation` — Automatic rotation not enabled

**Amazon Bedrock** (2 checks)
- `check-no-logging` — Model invocation logging disabled
- `check-no-budget-limits` — No AWS Budget for Bedrock spend

**KMS** (1 check)
- `check-no-key-rotation` — Customer-managed keys without automatic rotation

**ACM** (1 check)
- `check-expiring-certificates` — Certificates expiring within 30 days (configurable via `--days`)

**ElastiCache** (2 checks)
- `check-no-encryption-at-rest` — Redis replication groups without encryption at rest
- `check-no-encryption-in-transit` — Redis replication groups without encryption in transit

**SNS** (1 check)
- `check-no-encryption` — Topics without server-side encryption

**SQS** (1 check)
- `check-no-encryption` — Queues without server-side encryption

**ECS** (1 check)
- `check-privileged-tasks` — Task definitions with privileged containers (container escape risk)

**SSM** (1 check)
- `check-non-compliant-patches` — Instances with missing security patches

### 🔧 Enhanced Checks

**IAM `check-unused-roles`**
- Default threshold reduced from 90 to 30 days
- Roles with AdministratorAccess or `*:*` now flagged as `critical` instead of `high`
- Admin detection via attached policies and inline policy analysis

**EC2 `check-imdsv1-oversized`** (new)
- Cross-references IMDSv1 + low CPU utilization into a single `critical` finding
- Instances that are both SSRF-vulnerable and wasting money get highest remediation priority

**RDS `check-no-event-subscription`** (new)
- Detects missing RDS event subscriptions for instance events

**S3 `check-no-account-public-access-block`** (new)
- Checks if account-level S3 Block Public Access is fully enabled
- Flags as critical if not configured at all

### 📊 Summary
- **Total services**: 30 (was 17)
- **New checks this release**: 25+
- **Total commands**: ~240+

---

## Version 1.9.0 - Security Audit Expansion, WAFv2 & Public Exposure (2025-01-XX)

### 🌐 New Command: `kosty public-exposure`
Full external attack surface mapping. Scans 15 resource types across your AWS account, identifies everything reachable from the internet, and evaluates protection layers for each exposed resource.

**Resources scanned:**
- ALB/NLB (internet-facing) — checks WAF, HTTPS
- EC2 (public IP) — checks SG port restrictions, IMDSv2
- S3 (public ACL/policy) — checks CloudFront, PublicAccessBlock
- RDS (PubliclyAccessible) — checks SG, encryption
- RDS & EBS Snapshots (public) — always critical
- API Gateway (public endpoints) — checks WAF, throttling, auth
- Lambda Function URLs — checks auth type, CORS
- CloudFront distributions — checks WAF, HTTPS, TLS 1.2
- OpenSearch domains (no VPC) — checks access policy, encryption, HTTPS
- Redshift clusters (PubliclyAccessible) — checks SG, encryption
- EKS (public API endpoint) — checks private endpoint, CIDR restrictions, audit logging
- ECR Public repositories — always flagged
- SNS topics (wildcard policy) — no-condition Allow to *
- SQS queues (wildcard policy) — no-condition Allow to *

**Findings are classified into three tiers:**
- 🔴 **Exposed & Unprotected** — no protections detected, immediate action required
- 🟡 **Exposed & Partially Protected** — some protections in place, gaps remain
- 🟢 **Exposed & Protected** — all evaluated protections are active

```bash
kosty public-exposure --region eu-west-3 --output console
kosty public-exposure --organization --output json
```

### 🛡️ New Service: AWS WAFv2 (6 checks)
- `check-unassociated-acls` — Web ACLs not attached to any resource
- `check-missing-managed-rules` — Missing Core Rule Set or IP Reputation
- `check-no-rate-based-rule` — No DDoS/brute-force rate limiting (Critical)
- `check-no-logging` — WAF logging disabled
- `check-default-count-action` — Critical rules set to Count instead of Block
- `check-no-bot-control` — No Bot Control rule group configured
- Handles both REGIONAL and CLOUDFRONT scopes automatically

### 🔐 IAM: +8 Security Checks
- `check-root-mfa` — Root account MFA status (Critical)
- `check-all-users-mfa` — Console users without MFA
- `check-unused-access-keys` — Active keys unused for 90+ days
- `check-inline-policies` — Inline policies on users, roles, and groups
- `check-passrole-permissions` — iam:PassRole with wildcard resource (Critical)
- `check-shared-lambda-roles` — Lambda functions sharing execution roles
- `check-multiple-active-keys` — Users with multiple active access keys
- `check-wildcard-assume-role` — sts:AssumeRole with wildcard resource (Critical)

### 🔐 IAM: Privilege Escalation Detection (21 patterns)
- `check-privilege-escalation` — Scans all users and roles for 21 known escalation paths
- Detects direct escalation (CreatePolicyVersion, AttachUserPolicy, AddUserToGroup, etc.)
- Detects credential theft (CreateAccessKey, CreateLoginProfile for other users)
- Detects compute-based escalation (PassRole + Lambda/EC2/ECS/CloudFormation/Glue)
- Checks for permission boundaries as a mitigating factor
- Optional `--deep` flag confirms findings via `iam:SimulatePrincipalPolicy` (zero false positives)

### 🌐 API Gateway: +8 Security Checks
- `check-no-waf` — Stages not protected by WAF
- `check-no-authorization` — Endpoints with AUTH_TYPE=NONE
- `check-no-logging` — Access/execution logging disabled
- `check-no-throttling` — No custom throttling (cost-bleeding risk)
- `check-private-api-no-policy` — Private APIs without resource policy
- `check-http-api-no-jwt` — HTTP APIs (v2) without JWT authorizer
- `check-custom-domain-no-tls12` — Custom domains not enforcing TLS 1.2
- `check-missing-request-validation` — Methods without request validation
- `check-cloudfront-bypass` — APIs behind CloudFront without resource policy restricting direct access

### 🛡️ WAFv2: Enhanced Managed Rules Check
- `check-missing-managed-rules` now verifies 4 rule groups: Core Rule Set, IP Reputation, SQLi Rule Set, and Known Bad Inputs (Log4j, etc.)

### 🗃️ RDS: +2 Checks
- `check-no-auto-minor-upgrade` — Auto minor version upgrade disabled (Security)
- `check-no-performance-insights` — Performance Insights disabled (Cost)

### 🗄️ S3: +2 Checks
- `check-no-object-lock` — Object Lock not enabled, no ransomware protection (Security)
- `check-no-cross-region-replication` — No cross-region replication configured (DR)

### 🛡️ WAFv2: +1 Check
- `check-no-bot-control` — No Bot Control rule group configured

### ⚡ Performance Fix
- Fixed CloudWatch `check-unused-custom-metrics` hanging on accounts with many custom metrics
- Added configurable `--max-metrics` parameter (default: 50) via CLI or `kosty.yaml`
- Comprehensive scan now completes reliably on all account sizes

### 📊 Summary
- **Total services**: 17 (was 16)
- **New checks this release**: 26+
- **New standalone command**: `kosty public-exposure` (15 resource types)
- **Total commands**: ~240+

### 📖 Documentation
- Updated README.md with all new commands and examples
- Updated CLI_REFERENCE.md with WAFv2, IAM, API Gateway, RDS, S3 sections
- Internal PENDING_FEATURES.md tracker for audit coverage

---

## Version 1.6.1 - Bug Fixes (2025-01-16)

### 🐛 Bug Fixes
- **Profile Configuration**: Fixed profile settings not being applied in service commands
  - `execute_service_command` now properly merges profile config with CLI args
  - Ensures profile settings (regions, role_arn, MFA, exclusions) are respected
  - CLI arguments still take priority over profile settings

- **Audit Command**: Fixed undefined variables in audit command
  - Resolved NameError for 'org' and 'admin_account' variables
  - JSON and CSV report generation now works correctly

### 🔧 Technical Details
- Added `merge_with_cli_args()` call in `execute_service_command`
- Consistent behavior between `audit` command and individual service commands
- Profile-based AWS session (AssumeRole/MFA) now works for all commands

---

## Version 1.6.0 - Tag-Based Resource Exclusion (2025-01-16)

### 🏷️ Major Feature: Tag-Based Exclusion Filtering
- **Resource Filtering by Tags**: Skip resources based on AWS tags before auditing
  - Filter resources BEFORE expensive API calls (CloudWatch metrics, etc.)
  - Support for exact match (key + value) or key-only matching
  - Works across all 16 services with tag support
  - Cumulative exclusions: profile tags add to global tags

### 🎯 Configuration Format
```yaml
exclude:
  tags:
    # Exact match (key + value)
    - key: "kosty_ignore"
      value: "true"
    
    # Key match (any value)
    - key: "Environment"
      value: "production"
    
    # Key exists (no value specified)
    - key: "Protected"
```

### 🚀 Usage Examples
```bash
# Tag your resources
aws ec2 create-tags --resources i-1234567890abcdef0 \
  --tags Key=kosty_ignore,Value=true

# Run audit - tagged resource will be skipped
kosty audit

# Per-profile tag exclusions
kosty audit --profile production
```

### 📊 Implementation Coverage
- **16 Services Updated**: ~160 methods modified across all services
- **Performance Optimized**: Resources filtered before expensive operations
- **Universal Support**: Works with EC2, S3, RDS, Lambda, EBS, and all other services

### 💡 Use Cases
- **Skip Production Resources**: Exclude production environment from audits
- **Protected Infrastructure**: Mark critical resources to skip
- **Temporary Resources**: Exclude temporary/testing resources
- **Customer-Specific**: Different exclusions per customer profile

### 🔧 Technical Implementation
- **tag_utils Module**: New utility module for tag filtering logic
- **ConfigManager Enhancement**: Tag exclusion support in configuration
- **Service Integration**: All services pass config_manager and filter by tags
- **Early Filtering**: Skip resources before CloudWatch/API calls

### 📖 Documentation Updates
- Updated `kosty.yaml.example` with tag exclusion examples
- Enhanced `CONFIGURATION.md` with comprehensive tag filtering guide
- Added examples for common use cases

---

## Version 1.5.1 - Multi-Profile Parallel Execution (2025-01-15)

### 🔄 Major Feature: Multi-Profile Audits
- **Parallel Profile Execution**: Run audits across all profiles simultaneously
  - New `--profiles` flag to execute all configured profiles
  - Parallel execution with configurable concurrency (default: 3 profiles at once)
  - Individual reports per profile with timestamp suffixes
  - Aggregated summary report across all profiles
  - Continue on errors - failed profiles don't stop others

### 📊 Enhanced Reporting
- **Profile-Specific Reports**: Each profile gets its own output file
  - Format: `output/kosty_audit_<profile>_<timestamp>.json`
  - Includes profile name, timestamp, and configuration metadata
  - Separate CSV reports per profile when using `--output csv`
  
- **Summary Report**: Consolidated view across all profiles
  - Total issues and savings aggregated
  - Per-profile breakdown with success/failure status
  - Error tracking for failed profiles
  - Format: `output/kosty_summary_<timestamp>.json`

### 🚀 Usage Examples
```bash
# Run all profiles in parallel
kosty audit --profiles --output all

# Control parallel execution
kosty audit --profiles --max-parallel-profiles 5

# Multi-profile with custom config
kosty audit --config-file /path/to/config.yaml --profiles

# Override settings for all profiles
kosty audit --profiles --max-workers 10 --output json
```

### 📈 Console Output
- Real-time progress tracking per profile
- Individual profile completion status with issue counts and savings
- Final summary table showing all profiles with totals
- Error reporting for failed profiles

### 🔧 Technical Implementation
- **MultiProfileRunner Class**: New module for parallel profile execution
- **ThreadPoolExecutor**: Efficient parallel processing with configurable workers
- **Profile Isolation**: Each profile runs independently with its own config
- **Error Resilience**: Exceptions in one profile don't affect others

### 💡 Use Cases
- **Multi-Customer Audits**: Run audits for all customers in one command
- **Environment Comparison**: Compare dev, staging, and production simultaneously
- **Regional Analysis**: Audit multiple regions with different configurations
- **Time Efficiency**: Reduce total audit time with parallel execution

---

## Version 1.4.0 - Cost Quantification Engine & Phase 2 Services (2025-11-02)

### 💰 Major Feature: Cost Quantification Engine
- **Financial ROI Calculations**: Transform Kosty from "linter" to "FinOps ROI tool"
  - Real monthly and annual savings calculations in USD
  - AWS Pricing API integration with intelligent fallbacks
  - 11 services now provide quantified cost savings
  - Dashboard displays total estimated savings prominently

### 🚀 Phase 2 Services - Complex Cost Analysis
- **RDS Cost Optimization**: Oversized database instance detection
  - CPU utilization analysis (<20% = oversized)
  - 50% savings estimation for rightsizing
  - Support for 10+ common instance types (db.t3.micro → db.r5.8xlarge)
  - Fallback pricing for API reliability

- **Lambda Cost Optimization**: Over-provisioned memory detection
  - Memory optimization analysis (>512MB threshold)
  - Free tier calculations (1M requests + 400K GB-seconds/month)
  - Request and duration cost components
  - 50% memory reduction savings estimation

- **DynamoDB Cost Optimization**: Idle table detection
  - Provisioned capacity analysis (RCU/WCU)
  - Free tier support (25 RCU + 25 WCU + 25 GB/month)
  - On-demand optimization recommendations (80% savings)
  - Low utilization threshold detection

### 💵 Enhanced Cost Calculation Coverage
**11 Services with Cost Quantification:**
- **Phase 1**: EBS, EC2, EIP, NAT Gateway, Load Balancer, S3, Snapshots, Backup
- **Phase 2**: RDS, Lambda, DynamoDB

**Services with Audit Only** (no cost calculation):
- IAM, CloudWatch, Route53, API Gateway, Security Groups

### 🎨 Dashboard Cost Integration
- **Total Estimated Savings Card**: Prominent green card showing monthly/annual savings
- **Individual Cost Display**: Each cost issue shows "$X.XX/month" in green
- **Cost Aggregation**: Service-level cost summaries and totals
- **ROI Calculator**: Visual impact representation with piggy bank icons

### 📊 Enhanced Reporting
- **Console Reports**: Cost savings included in summary with top issues by savings
- **JSON Reports**: `monthly_cost` and `cost_currency` fields added to cost findings
- **CSV Reports**: "Monthly Cost (USD)" and "Annual Cost (USD)" columns
- **All Formats**: Backward compatible with existing workflows

### ⚠️ Cost Calculation Disclaimer
**Important**: Cost estimates are based on AWS Pricing API and standard rates. Actual costs may vary due to:
- Reserved Instance discounts
- Savings Plans
- Volume discounts
- Regional pricing variations
- Custom enterprise agreements
- Spot instance pricing

Use estimates for relative comparison and optimization prioritization.

### 🔧 Technical Implementation
- **PricingService Class**: AWS Pricing API wrapper with intelligent caching
- **CostCalculator Class**: Service-specific cost calculation logic
- **Fallback Pricing**: Fixed prices for unreliable API services (EIP, S3, Snapshots)
- **Free Tier Support**: Accurate calculations for AWS Free Tier limits
- **Regional Pricing**: Support for 16+ AWS regions with location mapping

### 📈 Example Cost Savings
```bash
# Real examples from cost calculations:
RDS db.r5.4xlarge (5% CPU): $700.80/month savings
EC2 m5.2xlarge stopped: $280.32/month savings  
Lambda 3008MB→1024MB: $0.68/month savings
EBS 100GB orphaned: $10.00/month savings
EIP unattached: $3.60/month savings
```

---

## Version 1.3.8 - Enterprise Storage Support with Network Share Compatibility (2025-01-XX)

### 🌐 Enterprise Storage Features
- **Universal Storage Support**: Added `--save-to` parameter supporting multiple storage types
  - **S3 Buckets**: `kosty audit --save-to s3://my-bucket/reports/`
  - **Local Paths**: `kosty audit --save-to /home/user/reports/`
  - **Network Shares**: `kosty audit --save-to \\server\share\reports\` (Windows UNC)
  - **Network Mounts**: `kosty audit --save-to /mnt/nas/reports/` (Linux/macOS)

### 🔒 Advanced Storage Features
- **S3 Integration**: Full S3 support with enterprise-grade security
  - Automatic AES256 server-side encryption
  - Proper IAM permission validation
  - Clear error messages for access issues
  - Support for custom S3 paths and prefixes

- **Network Share Support**: Robust handling of enterprise network storage
  - Windows UNC path detection (`\\server\share` and `//server/share`)
  - Linux/macOS mount point detection (`/mnt/`, `/media/`, `/Volumes/`)
  - Network connectivity validation with timeouts
  - Automatic directory creation for network paths

### ⚡ Performance & Reliability
- **Upfront Validation**: Storage access validated before starting scans
  - Prevents wasted time on failed scans
  - Clear error messages with actionable suggestions
  - Test write operations to verify permissions

- **Timeout Management**: Smart timeout handling for network operations
  - 10-second timeout for connectivity validation
  - 30-second timeout for file write operations
  - Prevents hanging on unreachable network shares

### 🏢 Enterprise Workflow Integration
- **All 147 Commands**: Every service command supports `--save-to`
  - Individual services: `kosty ec2 check-oversized-instances --save-to \\nas\reports\`
  - Complete audits: `kosty audit --organization --save-to s3://audit-bucket/`
  - Targeted audits: `kosty s3 security-audit --save-to /mnt/shared/s3/`

- **Flexible File Management**: Intelligent file handling
  - Automatic directory creation for local and network paths
  - Descriptive filenames with timestamps
  - Support for both directory and specific file paths

### 🔧 Technical Improvements
- **StorageManager Class**: New centralized storage management
  - Async operations for better performance
  - Unified interface for all storage types
  - Comprehensive error handling and validation

- **Enhanced Reporter**: Updated reporting system
  - Async save methods for custom storage locations
  - Integration with StorageManager for all output formats
  - Maintains backward compatibility with existing workflows

### 📝 Usage Examples
```bash
# S3 storage with organization scan
kosty audit --organization --save-to s3://company-audits/2025/

# Network share for individual service
kosty ec2 audit --save-to \\fileserver\aws-reports\ec2\

# Linux NAS mount for security audit
kosty iam security-audit --save-to /mnt/nas/security/iam/

# macOS network volume
kosty s3 check-public-buckets --save-to /Volumes/SharedDrive/s3-audit/
```

---

## Version 1.3.3 - PyPI Distribution & Individual Service Cross-Account Support (2025-10-29)

### 📦 PyPI Distribution
- **Official PyPI Package**: Kosty is now available on PyPI for easy installation
  - Install with: `pip install kosty`
  - Automatic dependency management
  - No need to clone repository for basic usage
  - Simplified installation process for end users

### 🔧 Cross-Account Role Support for Individual Services
- **Fixed Individual Service Commands**: All service commands now support cross-account parameters
  - `--cross-account-role` and `--org-admin-account-id` work with all services
  - Enables independent service scanning in large organizations
  - Perfect for splitting long-running organization scans into smaller chunks
  - Example: `kosty ec2 audit --organization --cross-account-role MyRole`

### 📚 Documentation Updates
- Updated installation instructions to prioritize pip installation
- Enhanced examples with pip-based workflow
- Improved getting started guide for new users

---

## Version 1.3.1 - Organization Pagination Fix (2025-10-29)

### 🐛 Critical Bug Fix
- **Organization Account Pagination**: Fixed issue where only the first 20 accounts were scanned in large organizations
  - Replaced direct `list_accounts()` call with `get_paginator('list_accounts')`
  - Now properly retrieves all accounts regardless of organization size
  - Maintains filtering of suspended accounts (`Status == 'ACTIVE'`)
  - Ensures complete coverage for organizations with 20+ accounts

### 🏢 Impact
- Organizations with more than 20 accounts now get full audit coverage
- No performance impact for smaller organizations
- Maintains existing async execution and error handling

---

## Version 1.3.0 - Cross-Account Role Configuration & Enhanced Error Handling (2025-10-29)

### 🔐 New Cross-Account Features
- **Configurable Cross-Account Roles**: Added `--cross-account-role` parameter to specify custom role names
  - Default remains `OrganizationAccountAccessRole` for backward compatibility
  - Example: `kosty audit --organization --cross-account-role MyCustomRole`
  - Addresses environments with different role naming conventions

- **Separate Organizational Admin Account**: Added `--org-admin-account-id` parameter
  - Supports scenarios where the current account lacks Organizations API access
  - Example: `kosty audit --organization --org-admin-account-id 123456789012`
  - Kosty first assumes a role in the specified admin account before listing organization accounts

### ⚡ Enhanced Error Handling
- **Upfront Organizations Validation**: Added pre-flight checks for Organizations API access
  - Fails fast with clear error messages instead of letting each service fail individually
  - Provides actionable suggestions for permission issues
  - Detects common scenarios: not in organization, insufficient permissions, role not found

### 🔧 Technical Improvements
- **Smart Permission Validation**: Validates access before starting comprehensive scans
- **Improved Error Messages**: Clear, actionable feedback for configuration issues
- **Better User Experience**: Immediate feedback on access problems with suggested solutions
- **Flexible IAM Support**: Works with various organizational structures and role configurations

### 📝 Documentation Updates
- Added comprehensive cross-account role configuration guide
- Enhanced troubleshooting section with common scenarios
- Updated examples for various organizational setups
- Added IAM policy examples for cross-account access

### 🐛 Bug Fixes
- Fixed CSV export errors with varying field structures across services
- Resolved "Unknown" resource name display issues in EBS and other services
- Fixed CloudWatch timezone comparison errors
- Improved resource name extraction from AWS tags

---

## Version 1.2.0 - Multi-Region Support & Modular CLI Architecture (2025-10-26)

### 🏗️ Architecture Improvements
- **Modular CLI Structure**: Refactored monolithic CLI (2000+ lines) into 19 organized files
  - One file per AWS service (~100 lines each) for better maintainability
  - Centralized common utilities in `utils.py` to reduce code duplication
  - Improved extensibility for adding new services and commands
  - Better collaboration with reduced Git conflicts

### 🌍 New Features
- **Multi-Region Support**: Added `--regions` parameter to scan multiple AWS regions simultaneously
  - Example: `kosty audit --regions us-east-1,eu-west-1,ap-southeast-1`
  - Workers are automatically distributed across regions for optimal performance
  - Compatible with all commands (audit, cost-audit, security-audit, individual checks)
  - Works with organization mode: `kosty audit --organization --regions us-east-1,eu-west-1`

### 📊 Dashboard Improvements
- **Enhanced Issue Navigation**: Added "View all issues" modal for services with 3+ issues
  - Modern, responsive design with grid layout
  - Click-through navigation: Dashboard → View All → Issue Details → Back to View All
  - Maintains context when navigating between issue details
- **Improved Data Compatibility**: Fixed dashboard parsing for mixed case field names
- **Better User Experience**: Smooth navigation flow with intuitive back buttons

### 🔧 Technical Improvements
- **CLI Maintainability**: Organized CLI commands by AWS service for better code organization
- **Standardized Output Format**: All services now output consistent lowercase field names (`type`, `severity`)
- **Performance Optimization**: Multi-region scanning with intelligent worker distribution
- **Code Quality**: Cleaned up field naming inconsistencies across all 16 services

### 📖 Documentation Updates
- Updated README.md with multi-region examples and usage patterns
- Enhanced DOCUMENTATION.md with comprehensive multi-region guidance
- Added troubleshooting section for multi-region scenarios

### 🐛 Bug Fixes
- Fixed dashboard chart rendering issues with mixed case JSON fields
- Resolved severity badge color display problems
- Corrected filter functionality for lowercase field names

---

## Version 1.1.0 - Dashboard & Organization Support (2025-10-25)

### 🎨 New Features
- **Visual Dashboard**: Modern React-based web dashboard with interactive charts
- **Organization Mode**: Scan entire AWS Organizations with `--organization` flag
- **Multiple Output Formats**: Console, JSON, CSV, and combined output with `--output all`

### 📊 Dashboard Features
- Interactive charts for service distribution, issue types, and severity levels
- Responsive design for desktop and mobile
- Issue filtering by service, type, and severity
- Detailed issue modals with comprehensive information
- Professional reporting capabilities

### 🏢 Organization Support
- Multi-account scanning across entire AWS Organizations
- Parallel processing with configurable worker counts
- Cross-account role assumption for secure access
- Consolidated reporting across all accounts

---

## Version 1.0.0 - Initial Release (2025-10-24)

### 🚀 Core Features
- **16 AWS Services**: Comprehensive coverage of core AWS infrastructure
- **147 Total Commands**: Complete audit, targeted audits, and individual checks
- **Cost Optimization**: Identify unused resources, oversized instances, and waste
- **Security Analysis**: Detect misconfigurations, public access, and vulnerabilities

### 🔍 Service Coverage
- **Compute**: EC2, Lambda
- **Storage**: S3, EBS, Snapshots  
- **Database**: RDS, DynamoDB
- **Network**: EIP, Load Balancer, NAT Gateway, Security Groups, Route53
- **Security**: IAM
- **Management**: CloudWatch, Backup
- **Application**: API Gateway

### ⚡ Performance Features
- Parallel processing with configurable workers
- Read-only operations for safe analysis
- Efficient API usage with intelligent throttling
- Comprehensive error handling and logging

### 📋 Command Structure
- Global audit command for all services
- Service-specific audit commands
- Individual check commands for granular analysis
- Flexible output formats and filtering options

---

## Upcoming

- `--verbose` flag for debug output (check-by-check timing, errors, session details)
- Compliance mapping (CIS, PCI-DSS, GDPR) on findings via `compliance_ids`
- Plugin integrity signing for the Pro version (GPG-signed manifest)

---

## 🤝 Contributing

We welcome contributions! See our [Contributing Guide](CONTRIBUTING.md) for details on:
- Reporting bugs and feature requests
- Adding new service checks
- Improving documentation
- Code contributions and pull requests

## 📞 Support

- **Documentation**: [docs/DOCUMENTATION.md](docs/DOCUMENTATION.md)
- **Issues**: [GitHub Issues](https://github.com/yassirkachri/kosty/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yassirkachri/kosty/discussions)

---

**💰 Happy cost optimizing with Kosty!**