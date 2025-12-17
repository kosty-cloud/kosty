# Multi-Profile Audit Guide

Run audits across multiple profiles in parallel for efficient multi-customer or multi-environment analysis.

## Quick Start

```bash
# Run all profiles from config file
kosty audit --profiles --output all

# Control parallel execution (default: 3)
kosty audit --profiles --max-parallel-profiles 5

# Use custom config file
kosty audit --config-file /path/to/config.yaml --profiles
```

## Configuration

Create a config file with multiple profiles:

```yaml
# kosty.yaml
default:
  regions:
    - us-east-1
  max_workers: 5

profiles:
  customer01:
    regions:
      - us-east-1
    max_workers: 10
    exclude:
      services:
        - route53
  
  customer02:
    regions:
      - eu-west-1
    max_workers: 8
    thresholds:
      ec2_cpu: 15
  
  production:
    regions:
      - us-east-1
      - eu-west-1
    max_workers: 15
    role_arn: "arn:aws:iam::123456789012:role/AuditRole"
```

## Output Structure

When using `--profiles`, Kosty generates:

```
output/
├── kosty_audit_customer01_20250115_103000.json
├── kosty_audit_customer02_20250115_103030.json
├── kosty_audit_production_20250115_103100.json
└── kosty_summary_20250115_103100.json
```

### Individual Profile Reports

Each profile gets its own report with:
- Profile name and timestamp
- Configuration used (regions, thresholds, exclusions)
- All issues found
- Total savings calculated

```json
{
  "profile": "customer01",
  "timestamp": "2025-01-15T10:30:00Z",
  "total_issues": 15,
  "total_savings": 1234.56,
  "results": { ... }
}
```

### Summary Report

Aggregated view across all profiles:

```json
{
  "timestamp": "2025-01-15T10:31:00Z",
  "total_profiles": 3,
  "successful_profiles": 3,
  "failed_profiles": 0,
  "total_issues": 46,
  "total_savings": 5257.89,
  "profiles": {
    "customer01": {
      "issues": 15,
      "savings": 1234.56,
      "timestamp": "2025-01-15T10:30:00Z"
    },
    "customer02": { ... },
    "production": { ... }
  }
}
```

## Console Output

Real-time progress tracking:

```
🚀 Running audits for 3 profiles in parallel (max 3 concurrent)
📋 Profiles: customer01, customer02, production

[customer01] Starting audit...
[customer02] Starting audit...
[production] Starting audit...
[customer01] ✓ Completed: 15 issues, $1,234.56/month
[customer02] ✓ Completed: 8 issues, $567.00/month
[production] ✓ Completed: 23 issues, $3,456.33/month

======================================================================
MULTI-PROFILE AUDIT SUMMARY
======================================================================
Total Profiles: 3
Successful: 3
Failed: 0

Total Issues: 46
Total Savings: $5,257.89/month ($63,094.68/year)

----------------------------------------------------------------------
Profile              Issues     Monthly Savings     
----------------------------------------------------------------------
customer01           15         $  1,234.56/month
customer02           8          $    567.00/month
production           23         $  3,456.33/month
======================================================================
```

## Use Cases

### Multi-Customer Audits

Run audits for all customers in one command:

```yaml
profiles:
  acme_corp:
    role_arn: "arn:aws:iam::111111111111:role/AuditRole"
    regions: [us-east-1]
  
  globex_inc:
    role_arn: "arn:aws:iam::222222222222:role/AuditRole"
    regions: [eu-west-1]
  
  initech:
    role_arn: "arn:aws:iam::333333333333:role/AuditRole"
    regions: [ap-southeast-1]
```

```bash
kosty audit --profiles --output all
```

### Environment Comparison

Compare dev, staging, and production:

```yaml
profiles:
  development:
    regions: [us-east-1]
    thresholds:
      ec2_cpu: 30  # More lenient for dev
  
  staging:
    regions: [us-east-1]
    thresholds:
      ec2_cpu: 25
  
  production:
    regions: [us-east-1, eu-west-1]
    thresholds:
      ec2_cpu: 15  # Stricter for prod
```

### Regional Analysis

Audit multiple regions with different configurations:

```yaml
profiles:
  us_regions:
    regions: [us-east-1, us-west-2]
    max_workers: 10
  
  eu_regions:
    regions: [eu-west-1, eu-central-1]
    max_workers: 10
  
  apac_regions:
    regions: [ap-southeast-1, ap-northeast-1]
    max_workers: 10
```

## Performance Tuning

### Parallel Profile Execution

Control how many profiles run simultaneously:

```bash
# Conservative (good for limited resources)
kosty audit --profiles --max-parallel-profiles 2

# Balanced (default)
kosty audit --profiles --max-parallel-profiles 3

# Aggressive (good for powerful machines)
kosty audit --profiles --max-parallel-profiles 5
```

### Per-Profile Workers

Each profile can have its own worker count:

```yaml
profiles:
  small_account:
    max_workers: 5  # Fewer resources
  
  large_account:
    max_workers: 20  # More resources
```

## Error Handling

Multi-profile execution continues even if one profile fails:

```
[customer01] ✓ Completed: 15 issues, $1,234.56/month
[customer02] ✗ Failed: Access denied for role assumption
[production] ✓ Completed: 23 issues, $3,456.33/month

----------------------------------------------------------------------
ERRORS:
  [customer02] Access denied for role assumption
```

Failed profiles are tracked in the summary report:

```json
{
  "failed_profiles": 1,
  "errors": {
    "customer02": {
      "profile": "customer02",
      "status": "error",
      "error": "Access denied for role assumption",
      "timestamp": "2025-01-15T10:30:45Z"
    }
  }
}
```

## CLI Override

Override config settings for all profiles:

```bash
# Override regions for all profiles
kosty audit --profiles --regions us-east-1

# Override max workers for all profiles
kosty audit --profiles --max-workers 15

# Override output format
kosty audit --profiles --output csv
```

## Best Practices

1. **Start Small**: Test with 2-3 profiles before scaling up
2. **Monitor Resources**: Watch CPU and memory usage during parallel execution
3. **Adjust Concurrency**: Use `--max-parallel-profiles` based on your machine
4. **Profile Naming**: Use descriptive names (customer01, prod_us, dev_eu)
5. **Error Tracking**: Check summary report for failed profiles
6. **Regular Audits**: Schedule multi-profile audits for consistent monitoring

## Troubleshooting

### Profile Not Found

```
⚠️  Profile 'customer01' not found, using 'default'
```

Check your config file has the profile defined under `profiles:`.

### Too Many Parallel Profiles

If you see performance issues:
- Reduce `--max-parallel-profiles`
- Reduce `max_workers` per profile
- Run profiles in batches

### Permission Errors

Each profile needs proper IAM permissions:
- Organizations API access (if using `--organization`)
- Cross-account role assumption (if using `role_arn`)
- Service-specific read permissions

## Examples

### Basic Multi-Profile

```bash
kosty audit --profiles
```

### With Custom Config

```bash
kosty audit --config-file ~/audits/config.yaml --profiles
```

### JSON Output Only

```bash
kosty audit --profiles --output json
```

### All Formats

```bash
kosty audit --profiles --output all
```

### Override Settings

```bash
kosty audit --profiles --regions us-east-1,eu-west-1 --max-workers 10
```
