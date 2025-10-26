# 🔧 Kosty CLI Reference

## 📋 Command Reference

### Global Commands

#### `kosty audit`
Comprehensive scan of all 16 AWS services.

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

### S3 Commands (14 total)

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
```

### RDS Commands (17 total)

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
kosty rds check-unused-parameter-groups
```

### IAM Commands (13 total)

#### Audit Commands
```bash
kosty iam audit [--days INT]
kosty iam cost-audit [--days INT]
kosty iam security-audit [--days INT]
```

#### Individual Checks
```bash
kosty iam check-root-access-keys
kosty iam check-unused-roles [--days INT]
kosty iam check-inactive-users [--days INT]
kosty iam check-old-access-keys [--days INT]
kosty iam check-wildcard-policies
kosty iam check-admin-no-mfa
kosty iam check-weak-password-policy
kosty iam check-no-password-rotation [--days INT]
kosty iam check-cross-account-no-external-id
kosty iam check-unused-groups [--days INT]
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