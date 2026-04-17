# 🔧 Kosty CLI Reference

## 📋 Command Reference

### Global Commands

#### `kosty audit`
Comprehensive scan of all 30 AWS services.

**Usage:**
```bash
kosty audit [OPTIONS]
```

**Options:**
- `--organization` - Scan entire AWS organization
- `--region TEXT` - AWS region to scan
- `--max-workers INTEGER` - Number of parallel workers (default: 10)
- `--output [console|json|csv]` - Output format (default: console)

**Examples:**
```bash
kosty audit
kosty audit --organization --max-workers 20
kosty audit --output json --region us-west-2
```

---

#### `kosty public-exposure`
External attack surface audit. Maps all publicly exposed resources across 15 resource types and evaluates protection layers (WAF, SG, TLS, auth, encryption).

**Usage:**
```bash
kosty public-exposure [OPTIONS]
```

**Examples:**
```bash
kosty public-exposure --region eu-west-3 --output console
kosty public-exposure --organization --output json
kosty public-exposure --regions us-east-1,eu-west-1 --output all
```

**Resources scanned:** ALB/NLB, EC2, S3, RDS, RDS Snapshots, EBS Snapshots, API Gateway, Lambda URLs, CloudFront, OpenSearch, Redshift, EKS, ECR Public, SNS, SQS

**Classification:**
- 🔴 Exposed & Unprotected (critical)
- 🟡 Exposed & Partially Protected (high)
- 🟢 Exposed & Protected (info)

---

## 🔍 Service Commands

All services follow the same command pattern:

### Standard Service Commands
```bash
kosty <service> audit           # Complete audit (cost + security)
kosty <service> cost-audit      # Cost optimization only
kosty <service> security-audit  # Security issues only
```

### Individual Check Commands
```bash
kosty <service> check-<issue>   # Specific issue check
```

---

## 📊 Service-Specific Commands

### EC2 Commands (16 total)

#### Audit Commands
```bash
kosty ec2 audit [--cpu-threshold INT] [--days INT]
kosty ec2 cost-audit [--cpu-threshold INT] [--days INT]
kosty ec2 security-audit
```

#### Individual Checks
```bash
kosty ec2 check-stopped-instances [--days INT]
kosty ec2 check-idle-instances [--cpu-threshold INT] [--days INT]
kosty ec2 check-oversized-instances [--cpu-threshold INT]
kosty ec2 check-previous-generation
kosty ec2 check-ssh-open
kosty ec2 check-rdp-open
kosty ec2 check-database-ports-open
kosty ec2 check-public-non-web
kosty ec2 check-old-ami [--days INT]
kosty ec2 check-imdsv1
kosty ec2 check-unencrypted-ebs
kosty ec2 check-no-recent-backup [--days INT]
kosty ec2 check-unused-key-pairs
```

### S3 Commands (17 total)

#### Audit Commands
```bash
kosty s3 audit [--days INT]
kosty s3 cost-audit [--days INT]
kosty s3 security-audit
```

#### Individual Checks
```bash
kosty s3 check-empty-buckets
kosty s3 check-incomplete-uploads [--days INT]
kosty s3 check-lifecycle-policy [--days INT]
kosty s3 check-public-read-access
kosty s3 check-public-write-access
kosty s3 check-encryption-at-rest
kosty s3 check-versioning-disabled
kosty s3 check-access-logging
kosty s3 check-bucket-policy-wildcards
kosty s3 check-public-snapshots
kosty s3 check-mfa-delete
kosty s3 check-no-object-lock
kosty s3 check-no-cross-region-replication
```

### RDS Commands (20 total)

#### Audit Commands
```bash
kosty rds audit [--days INT] [--cpu-threshold INT]
kosty rds cost-audit [--days INT] [--cpu-threshold INT]
kosty rds security-audit
```

#### Individual Checks
```bash
kosty rds check-idle-instances [--days INT] [--cpu-threshold INT]
kosty rds check-oversized-instances [--cpu-threshold INT]
kosty rds check-unused-read-replicas [--days INT]
kosty rds check-multi-az-non-prod
kosty rds check-long-backup-retention [--days INT]
kosty rds check-gp2-storage
kosty rds check-public-databases
kosty rds check-unencrypted-storage
kosty rds check-default-username
kosty rds check-wide-cidr-sg
kosty rds check-disabled-backups
kosty rds check-outdated-engine [--months INT]
kosty rds check-no-ssl-enforcement
kosty rds check-no-auto-minor-upgrade
kosty rds check-no-performance-insights
kosty rds check-unused-parameter-groups
```

### IAM Commands (22 total)

#### Audit Commands
```bash
kosty iam audit [--days INT]
kosty iam cost-audit [--days INT]
kosty iam security-audit [--days INT]
```

#### Individual Checks
```bash
kosty iam check-root-access-keys
kosty iam check-root-mfa
kosty iam check-all-users-mfa
kosty iam check-admin-no-mfa
kosty iam check-unused-roles [--days INT]
kosty iam check-inactive-users [--days INT]
kosty iam check-old-access-keys [--days INT]
kosty iam check-unused-access-keys [--days INT]
kosty iam check-multiple-active-keys
kosty iam check-wildcard-policies
kosty iam check-wildcard-assume-role
kosty iam check-passrole-permissions
kosty iam check-inline-policies
kosty iam check-shared-lambda-roles
kosty iam check-weak-password-policy
kosty iam check-no-password-rotation
kosty iam check-cross-account-no-external-id
kosty iam check-privilege-escalation [--deep]
```

**Privilege Escalation Detection:**
The `--deep` flag is available on `audit`, `security-audit`, and `check-privilege-escalation`. Without it, Kosty uses fast pattern matching (21 known escalation paths). With `--deep`, findings are confirmed via `iam:SimulatePrincipalPolicy` for zero false positives.

```bash
kosty iam audit --deep
kosty iam security-audit --deep
kosty iam check-privilege-escalation --deep
```

### Security Groups Commands (9 total)

#### Audit Commands
```bash
kosty sg audit
kosty sg cost-audit
kosty sg security-audit
```

#### Individual Checks
```bash
kosty sg check-unused-groups
kosty sg check-ssh-rdp-open
kosty sg check-database-ports-open
kosty sg check-all-ports-open
kosty sg check-complex-security-groups [--rule-threshold INT]
kosty sg check-wide-cidr-rules
```

### Lambda Commands (8 total)

#### Audit Commands
```bash
kosty lambda audit [--days INT]
kosty lambda cost-audit [--days INT]
kosty lambda security-audit
```

#### Individual Checks
```bash
kosty lambda check-unused-functions [--days INT]
kosty lambda check-over-provisioned-memory
kosty lambda check-long-timeout-functions
kosty lambda check-public-functions
kosty lambda check-outdated-runtime
```

### EBS Commands (12 total)

#### Audit Commands
```bash
kosty ebs audit [--days INT]
kosty ebs cost-audit [--days INT]
kosty ebs security-audit
```

#### Individual Checks
```bash
kosty ebs check-orphan-volumes
kosty ebs check-low-io-volumes
kosty ebs check-old-snapshots [--days INT]
kosty ebs check-gp2-volumes
kosty ebs check-unencrypted-orphan
kosty ebs check-unencrypted-in-use
kosty ebs check-public-snapshots
kosty ebs check-no-recent-snapshot [--days INT]
kosty ebs check-oversized-volumes
```

---

### WAFv2 Commands (9 total)

#### Audit Commands
```bash
kosty waf audit
kosty waf cost-audit
kosty waf security-audit
```

#### Individual Checks
```bash
kosty waf check-unassociated-acls
kosty waf check-missing-managed-rules
kosty waf check-no-rate-based-rule
kosty waf check-no-logging
kosty waf check-default-count-action
kosty waf check-no-bot-control
```

### API Gateway Commands (15 total)

#### Audit Commands
```bash
kosty apigateway audit [--days INT]
kosty apigateway cost-audit [--days INT]
kosty apigateway security-audit
```

#### Individual Checks
```bash
kosty apigateway check-unused-apis [--days INT]
kosty apigateway check-no-waf
kosty apigateway check-no-authorization
kosty apigateway check-no-logging
kosty apigateway check-no-throttling
kosty apigateway check-private-api-no-policy
kosty apigateway check-http-api-no-jwt
kosty apigateway check-custom-domain-no-tls12
kosty apigateway check-missing-request-validation
kosty apigateway check-cloudfront-bypass
```

### CloudTrail Commands (6 total)

#### Audit Commands
```bash
kosty cloudtrail audit
kosty cloudtrail security-audit
```

#### Individual Checks
```bash
kosty cloudtrail check-not-enabled
kosty cloudtrail check-no-log-validation
kosty cloudtrail check-no-encryption
```

### VPC Commands (5 total)

#### Audit Commands
```bash
kosty vpc audit
kosty vpc security-audit
```

#### Individual Checks
```bash
kosty vpc check-no-flow-logs
kosty vpc check-default-sg-open
```

### GuardDuty Commands (2 total)

```bash
kosty guardduty audit
kosty guardduty check-not-enabled
```

### AWS Config Commands (2 total)

```bash
kosty config audit
kosty config check-not-enabled
```

### Secrets Manager Commands (6 total)

#### Audit Commands
```bash
kosty secretsmanager audit [--days INT]
kosty secretsmanager cost-audit [--days INT]
kosty secretsmanager security-audit
```

#### Individual Checks
```bash
kosty secretsmanager check-unused-secrets [--days INT]
kosty secretsmanager check-no-rotation
```

### AI/ML Commands — `kosty ai`

#### Top-Level (Bedrock + SageMaker combined)
```bash
kosty ai audit [--days INT]
kosty ai cost-audit [--days INT]
kosty ai security-audit
```

#### Bedrock Subcommands
```bash
kosty ai bedrock audit
kosty ai bedrock cost-audit
kosty ai bedrock security-audit
kosty ai bedrock check-no-logging
kosty ai bedrock check-no-budget-limits
kosty ai bedrock check-no-guardrails
kosty ai bedrock check-shadow-ai
kosty ai bedrock check-no-vpc-endpoint
kosty ai bedrock check-custom-model-no-kms
kosty ai bedrock check-no-prompt-caching
kosty ai bedrock check-no-inference-profiles
```

#### SageMaker Subcommands
```bash
kosty ai sagemaker audit [--days INT]
kosty ai sagemaker cost-audit [--days INT]
kosty ai sagemaker security-audit
kosty ai sagemaker check-idle-endpoints [--days INT]
kosty ai sagemaker check-zombie-notebooks
kosty ai sagemaker check-no-spot-training
kosty ai sagemaker check-no-checkpointing
kosty ai sagemaker check-no-vpc-endpoint
kosty ai sagemaker check-notebook-direct-internet
kosty ai sagemaker check-notebook-root-access
```

### Standalone Bedrock Commands

These are also available directly (included in `kosty audit` full scan):
```bash
kosty bedrock audit
kosty bedrock cost-audit
kosty bedrock security-audit
kosty bedrock check-no-logging
kosty bedrock check-no-budget-limits
```

### KMS Commands (3 total)

```bash
kosty kms audit
kosty kms check-no-key-rotation
```

### ACM Commands (3 total)

```bash
kosty acm audit [--days INT]
kosty acm check-expiring-certificates [--days INT]
```

### ElastiCache Commands (4 total)

```bash
kosty elasticache audit
kosty elasticache security-audit
kosty elasticache check-no-encryption-at-rest
kosty elasticache check-no-encryption-in-transit
```

### SNS Commands (2 total)

```bash
kosty sns audit
kosty sns check-no-encryption
```

### SQS Commands (2 total)

```bash
kosty sqs audit
kosty sqs check-no-encryption
```

### ECS Commands (2 total)

```bash
kosty ecs audit
kosty ecs check-privileged-tasks
```

### SSM Commands (2 total)

```bash
kosty ssm audit
kosty ssm check-non-compliant-patches
```

---

## 🔧 Common Parameters

### Threshold Parameters
- `--cpu-threshold INTEGER` - CPU utilization threshold (default: 20)
- `--days INTEGER` - Days threshold for various checks (default varies by check)
- `--rule-threshold INTEGER` - Rule count threshold for complex security groups (default: 50)
- `--months INTEGER` - Months threshold for outdated resources (default: 12)

### Global Parameters
- `--organization` - Scan entire AWS organization
- `--region TEXT` - AWS region to scan (default: current region)
- `--max-workers INTEGER` - Number of parallel workers (default: 10)
- `--output [console|json|csv]` - Output format (default: console)

---

## 📊 Output Formats

### Console Output
Human-readable table format with color coding:
- 🔴 CRITICAL issues
- 🟠 HIGH issues  
- 🟡 MEDIUM issues
- 🔵 LOW issues

### JSON Output
Structured data format for programmatic use:
```json
{
  "service": "EC2",
  "account_id": "123456789012",
  "region": "us-east-1",
  "resource_name": "i-1234567890abcdef0",
  "resource_id": "i-1234567890abcdef0",
  "arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
  "issue": "Instance stopped for 7+ days",
  "type": "cost",
  "risk": "Waste $30-500/mo per instance",
  "severity": "HIGH",
  "details": {
    "instance_type": "t3.medium",
    "stopped_days": 14
  }
}
```

### CSV Output
Comma-separated values for spreadsheet analysis with columns:
- Service, AccountId, Region, ResourceName, ResourceId, ARN
- Issue, Type, Risk, Severity, Details

---

## 🚀 Exit Codes

- `0` - Success
- `1` - General error
- `2` - Invalid arguments
- `3` - AWS credentials error
- `4` - Permission denied
- `5` - Service unavailable

---

## 📈 Performance Guidelines

### Worker Count Recommendations
- **Single account**: 10-15 workers
- **Organization (< 10 accounts)**: 15-20 workers  
- **Organization (> 10 accounts)**: 20-30 workers
- **Rate limited environments**: 5-10 workers

### Memory Usage
- **Basic scan**: ~100MB RAM
- **Organization scan**: ~500MB-1GB RAM
- **Large organization (100+ accounts)**: 2GB+ RAM

---

**💡 For more examples and use cases, see the main [README.md](../README.md) and [DOCUMENTATION.md](DOCUMENTATION.md)**