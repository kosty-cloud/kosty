# 💡 Kosty Usage Examples

## One-Command Audit

```bash
# Full audit — all 30 services, cost + security
kosty audit --output all

# Console summary only
kosty audit --output console

# JSON report for dashboard
kosty audit --output json
open dashboard/index.html
```

## External Attack Surface

```bash
# Map everything publicly exposed
kosty public-exposure --output console

# Organization-wide
kosty public-exposure --organization --output json

# Multi-region
kosty public-exposure --regions us-east-1,eu-west-1 --output all
```

## Security Audits

```bash
# IAM privilege escalation (21 patterns)
kosty iam check-privilege-escalation --deep

# Full IAM security audit with deep scan
kosty iam security-audit --deep

# WAF hardening
kosty waf audit

# API Gateway security
kosty apigateway security-audit

# Foundational checks
kosty cloudtrail audit
kosty vpc check-no-flow-logs
kosty guardduty check-not-enabled
kosty config check-not-enabled
```

## Cost Optimization

```bash
# Oversized instances
kosty ec2 check-oversized-instances --cpu-threshold 20
kosty rds check-oversized-instances --cpu-threshold 20

# Unused resources
kosty ebs check-orphan-volumes
kosty eip check-unattached-eips
kosty nat check-unused-gateways
kosty lb check-no-healthy-targets
kosty secretsmanager check-unused-secrets

# Over-provisioned
kosty lambda check-over-provisioned-memory
```

## Service-Specific Audits

```bash
# Storage
kosty s3 audit
kosty ebs audit
kosty snapshots audit

# Database
kosty rds audit --cpu-threshold 20
kosty dynamodb audit

# Network
kosty sg audit
kosty lb audit

# Security
kosty iam audit --deep
kosty waf audit
kosty kms audit
kosty acm audit

# AI/ML
kosty bedrock audit

# Messaging
kosty sns audit
kosty sqs audit

# Containers
kosty ecs audit
kosty ssm audit
```

## Organization-Wide Scanning

```bash
# All services across all accounts
kosty audit --organization --max-workers 20 --output all

# Custom cross-account role
kosty audit --organization --cross-account-role MyAuditRole

# Separate admin account
kosty audit --organization --org-admin-account-id 123456789012

# Multi-region organization scan
kosty audit --organization --regions us-east-1,eu-west-1 --max-workers 20
```

## Multi-Profile Audits

```bash
# Run all profiles in parallel
kosty audit --profiles --output all

# Control concurrency
kosty audit --profiles --max-parallel-profiles 5

# Custom config file
kosty audit --config-file /path/to/config.yaml --profiles
```

## Output Options

```bash
# Console (default)
kosty audit --output console

# JSON (for dashboard and automation)
kosty audit --output json

# CSV (for spreadsheets)
kosty audit --output csv

# All formats at once
kosty audit --output all

# Save to specific location
kosty audit --output json --save-to ./reports
kosty audit --output json --save-to s3://my-bucket/audits/
```

## Individual Checks

### IAM
```bash
kosty iam check-root-access-keys
kosty iam check-root-mfa
kosty iam check-all-users-mfa
kosty iam check-old-access-keys --days 90
kosty iam check-unused-access-keys --days 90
kosty iam check-wildcard-policies
kosty iam check-passrole-permissions
kosty iam check-inline-policies
kosty iam check-shared-lambda-roles
kosty iam check-privilege-escalation --deep
```

### S3
```bash
kosty s3 check-public-read-access
kosty s3 check-encryption-at-rest
kosty s3 check-no-object-lock
kosty s3 check-no-account-public-access-block
```

### EC2
```bash
kosty ec2 check-ssh-open
kosty ec2 check-imdsv1
kosty ec2 check-oversized-instances --cpu-threshold 20
kosty ec2 check-stopped-instances --days 7
```

### WAF
```bash
kosty waf check-no-rate-based-rule
kosty waf check-missing-managed-rules
kosty waf check-no-logging
kosty waf check-no-bot-control
```

### API Gateway
```bash
kosty apigateway check-no-waf
kosty apigateway check-no-authorization
kosty apigateway check-no-throttling
kosty apigateway check-cloudfront-bypass
```
