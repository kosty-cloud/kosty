# Kosty Configuration Guide

Complete guide to configuring Kosty with YAML profiles for persistent settings, exclusions, and AWS authentication.

## Table of Contents

- [Quick Start](#quick-start)
- [Configuration File Location](#configuration-file-location)
- [Profile System](#profile-system)
- [Exclusions](#exclusions)
- [Thresholds](#thresholds)
- [AWS Authentication](#aws-authentication)
- [Priority Order](#priority-order)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)

## Quick Start

### Create Configuration File

```bash
# Copy example file
cp kosty.yaml.example kosty.yaml

# Edit with your settings
vim kosty.yaml
```

### Basic Usage

```bash
# Use default profile
kosty audit

# Use specific profile
kosty audit --profile customer01

# Use custom config file
kosty audit --config-file /path/to/config.yaml

# Override config with CLI args
kosty audit --profile customer01 --regions eu-west-1 --max-workers 30
```

## Configuration File Location

Kosty searches for configuration files in this order:

1. **Explicit path** (highest priority)
   ```bash
   kosty audit --config-file /etc/kosty/prod.yaml
   ```

2. **Current directory**
   - `./kosty.yaml`
   - `./kosty.yml`
   - `./.kosty.yaml`
   - `./.kosty.yml`

3. **Home directory** (lowest priority)
   - `~/.kosty/config.yaml`

If no configuration file is found, Kosty uses hardcoded defaults.

## Profile System

### Default Profile

The `default` profile is used when no `--profile` is specified:

```yaml
default:
  organization: true
  regions:
    - us-east-1
    - eu-west-1
  max_workers: 20
  output: json
```

```bash
kosty audit  # Uses 'default' profile
```

### Additional Profiles

Define multiple profiles for different environments:

```yaml
profiles:
  customer01:
    organization: false
    regions:
      - us-east-1
    role_arn: "arn:aws:iam::123456789012:role/MyRole"
    max_workers: 10
  
  production:
    organization: true
    regions:
      - us-east-1
      - us-west-2
    max_workers: 30
```

```bash
kosty audit --profile customer01
kosty audit --profile production
```

### Profile Configuration Options

| Option | Type | Description | Default |
|--------|------|-------------|---------|
| `organization` | boolean | Scan organization accounts | `false` |
| `regions` | list | AWS regions to scan | `['us-east-1']` |
| `max_workers` | integer | Concurrent workers | `5` |
| `output` | string | Output format (console/json/csv/all) | `console` |
| `save_to` | string | S3 or local path for reports | `null` |
| `cross_account_role` | string | Role name for cross-account | `OrganizationAccountAccessRole` |
| `org_admin_account_id` | string | Org admin account ID | `null` |
| `role_arn` | string | Role ARN to assume | `null` |
| `aws_profile` | string | AWS CLI profile name | `null` |
| `mfa_serial` | string | MFA device ARN | `null` |
| `duration_seconds` | integer | AssumeRole session duration | `3600` |

## Exclusions

### Global Exclusions

Applied to **all profiles**:

```yaml
exclude:
  accounts:
    - "123456789012"
  regions:
    - "ap-south-1"
  services:
    - "route53"
  arns:
    - "arn:aws:ec2:*:123456789012:instance/i-protected*"
```

### Profile-Specific Exclusions

Profile exclusions are added to global exclusions (cumulative):

```yaml
# Global
exclude:
  services:
    - "route53"

# Profile
profiles:
  customer01:
    exclude:
      services:
        - "dynamodb"

# Result when using --profile customer01:
# Both "route53" AND "dynamodb" are excluded
```

### Exclusion Types

#### 1. Account Exclusions

```yaml
exclude:
  accounts:
    - "123456789012"  # Sandbox
    - "987654321098"  # Legacy
```

**Effect**: These accounts are skipped during organization scans.

#### 2. Region Exclusions

```yaml
exclude:
  regions:
    - "ap-south-1"
    - "sa-east-1"
```

**Effect**: These regions are skipped in all scans.

#### 3. Service Exclusions

```yaml
exclude:
  services:
    - "route53"
    - "apigateway"
    - "dynamodb"
```

**Effect**: These services are completely skipped.

**Valid services:**
- `ec2`, `s3`, `rds`, `lambda`, `ebs`, `iam`, `eip`
- `lb`, `nat`, `sg`, `cloudwatch`, `dynamodb`
- `route53`, `apigateway`, `backup`, `snapshots`

#### 4. ARN Exclusions (with Wildcards)

```yaml
exclude:
  arns:
    # All EC2 instances in account
    - "arn:aws:ec2:*:123456789012:instance/*"
    
    # All buckets starting with "prod-"
    - "arn:aws:s3:::prod-*"
    
    # All RDS databases in us-east-1
    - "arn:aws:rds:us-east-1:*:db:*"
    
    # Specific protected instances
    - "arn:aws:ec2:us-east-1:123456789012:instance/i-protected123"
```

**Effect**: Individual resources matching these patterns are skipped.

#### 5. Tag Exclusions (NEW in v1.6.0)

```yaml
exclude:
  tags:
    # Exclude resources with exact tag key and value
    - key: "kosty_ignore"
      value: "true"
    
    # Exclude resources with tag key (any value)
    - key: "Environment"
      value: "production"
    
    # Exclude if tag key exists (regardless of value)
    - key: "Protected"
    
    # Exclude temporary resources
    - key: "Temporary"
```

**Effect**: Resources with matching tags are skipped during audits.

**How it works:**
- If `value` is specified: Tag must match both key AND value
- If `value` is omitted: Tag key must exist (any value matches)
- Case-sensitive matching
- Applied before API calls (saves time and API quota)

**Example use cases:**
```yaml
exclude:
  tags:
    # Skip all production resources
    - key: "Environment"
      value: "production"
    
    # Skip resources explicitly marked to ignore
    - key: "kosty_ignore"
      value: "true"
    
    # Skip all resources owned by specific team
    - key: "Team"
      value: "platform"
    
    # Skip any resource with "DoNotAudit" tag
    - key: "DoNotAudit"
```

**Supported services:**
- EC2 instances, EBS volumes, Snapshots
- S3 buckets
- RDS databases
- Lambda functions
- Load Balancers, NAT Gateways
- DynamoDB tables
- And more (all services with tag support)

## Thresholds

### Global Thresholds

Applied to **all profiles** by default:

```yaml
thresholds:
  ec2_cpu: 20              # EC2 oversized if CPU < 20%
  rds_cpu: 20              # RDS oversized if CPU < 20%
  lambda_memory: 512       # Lambda over-provisioned if > 512MB
  stopped_days: 7          # EC2 stopped for 7+ days
  idle_days: 7             # EC2 idle for 7+ days
  old_snapshot_days: 30    # Snapshots older than 30 days
```

### Profile Threshold Overrides

Profile thresholds replace global thresholds (only specified ones):

```yaml
# Global
thresholds:
  ec2_cpu: 20
  rds_cpu: 20
  stopped_days: 7

# Profile
profiles:
  customer01:
    thresholds:
      ec2_cpu: 15      # Override (more strict)
      stopped_days: 30 # Override (more lenient)
      # rds_cpu not specified, uses global value (20)

# Result when using --profile customer01:
# ec2_cpu: 15 (profile override)
# rds_cpu: 20 (global value)
# stopped_days: 30 (profile override)
```

### Available Thresholds

| Threshold | Service | Description | Default |
|-----------|---------|-------------|---------|
| `ec2_cpu` | EC2 | CPU utilization threshold | `20` |
| `rds_cpu` | RDS | CPU utilization threshold | `20` |
| `lambda_memory` | Lambda | Memory threshold (MB) | `512` |
| `stopped_days` | EC2 | Days instance stopped | `7` |
| `idle_days` | EC2 | Days instance idle | `7` |
| `old_snapshot_days` | Snapshots | Snapshot age (days) | `30` |

## AWS Authentication

Kosty supports three authentication methods (in priority order):

### 1. AssumeRole (Recommended for Multi-Account)

Best for managing multiple customer accounts securely:

```yaml
profiles:
  customer01:
    role_arn: "arn:aws:iam::123456789012:role/MyRole"
    duration_seconds: 3600  # 1 hour
```

```bash
kosty audit --profile customer01
# → Assumes role without MFA prompt
```

### 2. AWS CLI Profile

Best for local development with multiple AWS accounts:

```yaml
profiles:
  customer01:
    aws_profile: "customer01-prod"  # References ~/.aws/credentials
    regions:
      - us-east-1
```

```bash
kosty audit --profile customer01
# → Uses credentials from ~/.aws/credentials profile "customer01-prod"
```

**Setup AWS CLI profile:**
```bash
# Configure profile
aws configure --profile customer01-prod

# Or edit ~/.aws/credentials
[customer01-prod]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

### 3. Default Credentials

Best for CI/CD pipelines or EC2 instances with IAM roles:

```yaml
profiles:
  customer01:
    regions:
      - us-east-1
    # No role_arn or aws_profile = uses default credentials
```

Kosty will use credentials from:
1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
2. `~/.aws/credentials` (default profile)
3. `~/.aws/config` (default profile)
4. IAM role (if running on EC2/Lambda/ECS)

### AssumeRole with MFA

```yaml
profiles:
  customer01:
    role_arn: "arn:aws:iam::123456789012:role/MyRole"
    mfa_serial: "arn:aws:iam::123456789012:mfa/device"
    duration_seconds: 28800  # 8 hours
```

```bash
kosty audit --profile customer01
# → Prompts: "🔐 Enter MFA token for arn:aws:iam::123456789012:mfa/device: "
# → User enters: 123456
# → Assumes role with MFA
```

### Organization Scanning

```yaml
default:
  organization: true
  cross_account_role: "OrganizationAccountAccessRole"
  org_admin_account_id: "999999999999"  # Optional
```

**How it works:**
1. If `org_admin_account_id` is set, assume role in that account first
2. List all organization accounts
3. Assume `cross_account_role` in each account
4. Run scans in parallel

## Priority Order

Configuration values are resolved in this order (highest to lowest priority):

```
1. CLI Arguments (--region us-east-1)
   ↓
2. Profile Configuration (profiles.customer01.regions)
   ↓
3. Default Configuration (default.regions)
   ↓
4. Hardcoded Defaults (['us-east-1'])
```

### Example

```yaml
# Config file
default:
  regions:
    - us-east-1
    - eu-west-1
  max_workers: 20

profiles:
  customer01:
    regions:
      - us-west-2
    max_workers: 10
```

```bash
# Uses profile regions + max_workers
kosty audit --profile customer01
# → regions: [us-west-2], max_workers: 10

# CLI overrides profile
kosty audit --profile customer01 --regions eu-west-1 --max-workers 30
# → regions: [eu-west-1], max_workers: 30

# Uses default profile
kosty audit
# → regions: [us-east-1, eu-west-1], max_workers: 20
```

## Examples

### Example 1: Multi-Customer Setup

```yaml
exclude:
  services:
    - "route53"  # Never scan Route53

default:
  organization: false
  max_workers: 10

profiles:
  customer01:
    regions: [us-east-1]
    role_arn: "arn:aws:iam::111111111111:role/Audit"
    mfa_serial: "arn:aws:iam::999999999999:mfa/device"
  
  customer02:
    regions: [eu-west-1]
    role_arn: "arn:aws:iam::222222222222:role/Audit"
    mfa_serial: "arn:aws:iam::999999999999:mfa/device"
  
  customer03:
    regions: [ap-southeast-1]
    role_arn: "arn:aws:iam::333333333333:role/Audit"
    mfa_serial: "arn:aws:iam::999999999999:mfa/device"
```

```bash
kosty audit --profile customer01  # Scan customer 1
kosty audit --profile customer02  # Scan customer 2
kosty audit --profile customer03  # Scan customer 3
```

### Example 2: Environment-Based Thresholds

```yaml
thresholds:
  ec2_cpu: 20
  stopped_days: 7

profiles:
  production:
    regions: [us-east-1, us-west-2]
    thresholds:
      ec2_cpu: 30      # More lenient for prod
      stopped_days: 3  # More strict for prod
  
  development:
    regions: [us-east-1]
    thresholds:
      ec2_cpu: 10      # More strict for dev
      stopped_days: 30 # More lenient for dev
```

### Example 3: Protected Resources

```yaml
exclude:
  arns:
    # Protect all production databases
    - "arn:aws:rds:*:*:db:prod-*"
    
    # Protect specific EC2 instances
    - "arn:aws:ec2:us-east-1:123456789012:instance/i-critical123"
    
    # Protect all S3 buckets in specific account
    - "arn:aws:s3:::*"  # If in excluded account context
  
  tags:
    # Protect all production resources
    - key: "Environment"
      value: "production"
    
    # Protect critical infrastructure
    - key: "Critical"
      value: "yes"
```

### Example 4: Tag-Based Exclusions

```yaml
# Global tag exclusions
exclude:
  tags:
    - key: "kosty_ignore"
      value: "true"

profiles:
  production:
    regions: [us-east-1, eu-west-1]
    exclude:
      tags:
        # Additional exclusions for production profile
        - key: "Environment"
          value: "production"
        - key: "Critical"
  
  development:
    regions: [us-east-1]
    exclude:
      tags:
        # Exclude temporary dev resources
        - key: "Temporary"
        - key: "Testing"
```

**Usage:**
```bash
# Tag your resources
aws ec2 create-tags --resources i-1234567890abcdef0 \
  --tags Key=kosty_ignore,Value=true

# Run audit - tagged resource will be skipped
kosty audit --profile production
```

## Troubleshooting

### Configuration Not Found

```
⚠️  Profile 'customer01' not found, using 'default'
```

**Solution:** Check profile name spelling in `kosty.yaml`

### Validation Errors

```
❌ Configuration validation failed:
  • Invalid region: 'us-east-99'
  • Unknown service: 'bedrock'
```

**Solution:** Fix invalid values in config file

### AssumeRole Failed

```
❌ Failed to assume role: AccessDenied
💡 Using default credentials instead
```

**Solutions:**
- Check role ARN is correct
- Verify trust relationship allows your account
- Check MFA token is valid
- Verify role has required permissions

### MFA Prompt Not Appearing

**Cause:** `mfa_serial` not configured

**Solution:** Add `mfa_serial` to profile:
```yaml
profiles:
  customer01:
    role_arn: "arn:aws:iam::123456789012:role/MyRole"
    mfa_serial: "arn:aws:iam::123456789012:mfa/device"  # Add this
```

### Services Still Scanned Despite Exclusion

**Check:**
1. Service name is correct (lowercase: `ec2`, not `EC2`)
2. Config file is in correct location
3. Using correct profile: `--profile customer01`

### Regions Not Excluded

**Check:**
1. Region code is correct: `us-east-1` (not `us-east-1a`)
2. Exclusion is in correct section (global `exclude` or profile `exclude`)

## Additional Resources

- [Main Documentation](DOCUMENTATION.md)
- [CLI Reference](CLI_REFERENCE.md)
- [Release Notes](RELEASE_NOTES.md)
- [Example Config File](../kosty.yaml.example)

## Need Help?

- 📧 Email: yassir@kosty.cloud
- 🐛 Issues: https://github.com/kosty-cloud/kosty/issues
- 💬 Discussions: https://github.com/kosty-cloud/kosty/discussions
