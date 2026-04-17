# Kosty — Usage Examples

## Full Audit

```bash
# Everything, all formats
kosty audit --output all

# JSON for dashboard
kosty audit --output json
open dashboard/index.html

# Specific region
kosty audit --region eu-west-3 --output console
```

## Attack Surface

```bash
kosty public-exposure --output console
kosty public-exposure --organization --output json
kosty public-exposure --regions us-east-1,eu-west-1 --output all
```

## Security

```bash
# IAM — privilege escalation with confirmation
kosty iam check-privilege-escalation --deep
kosty iam security-audit --deep

# WAF
kosty waf audit

# API Gateway
kosty apigateway security-audit

# Foundational
kosty cloudtrail audit
kosty vpc check-no-flow-logs
kosty guardduty check-not-enabled
kosty config check-not-enabled
```

## Cost

```bash
# Oversized
kosty ec2 check-oversized-instances --cpu-threshold 20
kosty rds check-oversized-instances --cpu-threshold 20

# Unused
kosty ebs check-orphan-volumes
kosty eip check-unattached-eips
kosty nat check-unused-gateways
kosty lb check-no-healthy-targets
kosty secretsmanager check-unused-secrets

# Over-provisioned
kosty lambda check-over-provisioned-memory
```

## Per-Service

```bash
kosty s3 audit
kosty ebs audit
kosty rds audit --cpu-threshold 20
kosty iam audit --deep
kosty waf audit
kosty kms audit
kosty acm audit
kosty bedrock audit
kosty sns audit
kosty sqs audit
kosty ecs audit
kosty ssm audit
```

## Organization

```bash
kosty audit --organization --max-workers 20 --output all
kosty audit --organization --cross-account-role MyAuditRole
kosty audit --organization --org-admin-account-id 123456789012
kosty audit --organization --regions us-east-1,eu-west-1 --max-workers 20
```

## Multi-Profile

```bash
kosty audit --profiles --output all
kosty audit --profiles --max-parallel-profiles 5
kosty audit --config-file /path/to/config.yaml --profiles
```

## Output

```bash
kosty audit --output console
kosty audit --output json
kosty audit --output csv
kosty audit --output all
kosty audit --output json --save-to ./reports
kosty audit --output json --save-to s3://my-bucket/audits/
```

## Individual Checks

```bash
# IAM
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

# S3
kosty s3 check-public-read-access
kosty s3 check-encryption-at-rest
kosty s3 check-no-object-lock
kosty s3 check-no-account-public-access-block

# EC2
kosty ec2 check-ssh-open
kosty ec2 check-imdsv1
kosty ec2 check-oversized-instances --cpu-threshold 20
kosty ec2 check-stopped-instances --days 7

# WAF
kosty waf check-no-rate-based-rule
kosty waf check-missing-managed-rules
kosty waf check-no-logging
kosty waf check-no-bot-control

# API Gateway
kosty apigateway check-no-waf
kosty apigateway check-no-authorization
kosty apigateway check-no-throttling
kosty apigateway check-cloudfront-bypass
```
