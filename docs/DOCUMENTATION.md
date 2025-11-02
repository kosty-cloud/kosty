# 📖 Kosty Documentation

## 🎯 Overview

Kosty is a comprehensive AWS cost optimization and security audit CLI tool that helps you identify cost waste, security vulnerabilities, and compliance issues across 16 core AWS services. With 147 total commands, Kosty provides both high-level audits and granular individual checks for cost optimization and security hardening.

### 🎯 What Kosty Audits
- **💰 Cost Optimization**: Unused resources, oversized instances, idle services
- **🔐 Security Vulnerabilities**: Public access, unencrypted storage, open ports
- **🛡️ Compliance Issues**: Old access keys, weak configurations, policy violations

## 🔧 Installation

### Prerequisites
- Python 3.7 or higher
- AWS CLI configured with appropriate credentials

### Quick Installation (Recommended)
```bash
pip install kosty
```

### Install from Source
```bash
git clone https://github.com/kosty-cloud/kosty.git
cd kosty
./install.sh
```

### Development Installation
```bash
git clone https://github.com/kosty-cloud/kosty.git
cd kosty
pip install -e .
```

## 🚀 AWS Credentials Setup

### Option 1: AWS CLI Configuration
```bash
aws configure
```

### Option 2: Environment Variables
```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1
```

### Option 3: IAM Roles (Recommended for EC2)
Use IAM roles attached to your EC2 instances for secure, credential-free access.

### Required Permissions
Kosty requires read-only permissions for the following services:
- EC2, RDS, S3, IAM, Lambda, EBS
- EIP, Load Balancer, NAT Gateway, Security Groups
- Route53, CloudWatch, Backup, API Gateway
- DynamoDB, Snapshots

Example IAM policy:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:Describe*",
                "rds:Describe*",
                "s3:List*",
                "s3:Get*",
                "iam:List*",
                "iam:Get*",
                "lambda:List*",
                "lambda:Get*",
                "elasticloadbalancing:Describe*",
                "route53:List*",
                "cloudwatch:Describe*",
                "cloudwatch:List*",
                "backup:List*",
                "apigateway:GET",
                "dynamodb:List*",
                "dynamodb:Describe*"
            ],
            "Resource": "*"
        }
    ]
}
```

## 🏢 Organization Mode

### Setup
To scan across your entire AWS Organization:

1. **Enable Organization Access**:
   - Use credentials from the management account
   - Or use a role with `organizations:ListAccounts` permission

2. **Cross-Account Role Setup**:
   ```bash
   # Create a role in each member account with the required permissions
   # Trust the management account or scanning account
   ```

### Usage
```bash
# Scan entire organization
kosty audit --organization

# Organization scan with custom workers
kosty audit --organization --max-workers 20

# Organization scan for specific service
kosty ec2 audit --organization
```

## 💾 Custom Storage Locations

### Overview
Kosty supports saving reports to multiple storage types with the `--save-to` parameter:
- **S3 Buckets**: Enterprise cloud storage with encryption
- **Local Paths**: Local file system directories
- **Network Shares**: Windows UNC paths and Linux/macOS network mounts

### S3 Storage
```bash
# Save to S3 bucket root
kosty audit --save-to s3://my-audit-bucket/

# Save to S3 with custom path
kosty audit --save-to s3://company-reports/aws-audits/2025/

# Organization scan to S3
kosty audit --organization --save-to s3://org-audits/monthly/

# Individual service to S3
kosty ec2 check-oversized-instances --save-to s3://cost-reports/ec2/
```

#### S3 Features
- **Automatic Encryption**: AES256 server-side encryption applied automatically
- **Access Validation**: Upfront validation of S3 bucket permissions
- **Path Flexibility**: Support for bucket root or custom prefixes
- **Error Handling**: Clear error messages for permission or bucket issues

#### Required S3 Permissions
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:PutObjectAcl"
            ],
            "Resource": "arn:aws:s3:::your-bucket-name/*"
        }
    ]
}
```

### Local Storage
```bash
# Save to local directory
kosty audit --save-to /home/user/aws-reports/

# Save to specific file
kosty ec2 audit --save-to /home/user/ec2-audit.json

# Windows local path
kosty audit --save-to C:\\Reports\\AWS\\

# Relative path
kosty s3 audit --save-to ./reports/s3/
```

#### Local Storage Features
- **Automatic Directory Creation**: Creates directories if they don't exist
- **Permission Validation**: Tests write access before starting scans
- **Cross-Platform**: Works on Linux, macOS, and Windows
- **Flexible Paths**: Support for both directory and specific file paths

### Network Share Storage
```bash
# Windows UNC paths
kosty audit --save-to \\\\fileserver\\shared\\aws-reports\\
kosty ec2 audit --save-to \\\\nas\\audits\\ec2\\

# Alternative Windows format
kosty audit --save-to //fileserver/shared/aws-reports/

# Linux/macOS network mounts
kosty audit --save-to /mnt/nas/aws-reports/
kosty rds audit --save-to /media/shared/rds-audit/

# macOS network volumes
kosty audit --save-to /Volumes/SharedDrive/aws-audits/
```

#### Network Share Features
- **Automatic Detection**: Detects network paths automatically
- **Connectivity Validation**: Tests network connectivity with timeouts
- **Timeout Management**: 10s validation, 30s write timeouts
- **Cross-Platform**: Windows UNC, Linux/macOS mounts
- **Error Handling**: Clear messages for network connectivity issues

### Storage Validation
Kosty validates storage access before starting scans:

```bash
# Example validation output
$ kosty audit --save-to s3://non-existent-bucket/
❌ S3 access validation failed:
   • Bucket 'non-existent-bucket' does not exist
💡 S3 path format: s3://bucket-name/optional/path/

$ kosty audit --save-to \\\\offline-server\\share\\
🌐 Detected network path: \\\\offline-server\\share\\
   • Testing network connectivity...
❌ Network path access timeout:
   • Network path '\\\\offline-server\\share\\' is not accessible
   • Check network connectivity and share availability
```

### Usage Examples
```bash
# Enterprise workflow: Organization scan to S3
kosty audit --organization --max-workers 20 --save-to s3://company-audits/monthly/

# Development: Local testing
kosty ec2 check-oversized-instances --save-to ./test-reports/

# Team sharing: Network share
kosty iam security-audit --save-to \\\\teamnas\\security\\iam\\

# Multi-region to network mount
kosty audit --regions us-east-1,eu-west-1 --save-to /mnt/reports/multi-region/

# All output formats to S3
kosty audit --output all --save-to s3://reports/comprehensive/
```

## 🔐 Cross-Account Roles

### Custom Role Names
By default, Kosty uses `OrganizationAccountAccessRole` for cross-account access. You can specify a custom role name:

```bash
# Use custom role name
kosty audit --organization --cross-account-role MyCustomRole

# Apply to specific service
kosty ec2 audit --organization --cross-account-role MyAuditRole
```

### Separate Organizational Admin Account
If your current account doesn't have Organizations API access, specify the admin account:

```bash
# Assume role in org admin account first
kosty audit --organization --org-admin-account-id 123456789012

# Combine with custom role
kosty audit --organization --cross-account-role MyRole --org-admin-account-id 123456789012
```

### Setup Examples

#### Scenario 1: Custom Role Name
```bash
# Your organization uses "AuditRole" instead of "OrganizationAccountAccessRole"
kosty audit --organization --cross-account-role AuditRole
```

#### Scenario 2: Separate Admin Account
```bash
# Current account: 111111111111 (limited permissions)
# Org admin account: 222222222222 (has Organizations access)
# Target accounts: 333333333333, 444444444444, etc.

kosty audit --organization --org-admin-account-id 222222222222
```

#### Scenario 3: Both Custom Role and Admin Account
```bash
# Custom role "SecurityAuditRole" in org admin account "999999999999"
kosty audit --organization \
  --cross-account-role SecurityAuditRole \
  --org-admin-account-id 999999999999
```

### IAM Setup for Cross-Account Roles

#### Trust Policy Example
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::MANAGEMENT-ACCOUNT-ID:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "optional-external-id"
        }
      }
    }
  ]
}
```

### Error Handling
Kosty now validates Organizations access upfront and provides clear error messages:

- **Not in Organization**: Suggests using single account mode
- **Permission Denied**: Suggests using `--org-admin-account-id`
- **Role Not Found**: Indicates the specified role doesn't exist

## 📊 Command Structure

### Global Commands
```bash
kosty audit                    # Scan all 16 services
kosty audit --organization    # Organization-wide scan
```

### Service Commands
Each service follows the same pattern:
```bash
kosty <service> audit                    # Complete audit (cost + security)
kosty <service> cost-audit              # Cost optimization only
kosty <service> security-audit          # Security issues only
kosty <service> check-<specific-issue>  # Individual checks
```

### Common Options
All commands support:
- `--organization` - Scan entire AWS organization
- `--region TEXT` - Single AWS region to scan (default: us-east-1)
- `--regions TEXT` - Multiple AWS regions to scan (comma-separated, e.g., us-east-1,eu-west-1)
- `--max-workers INTEGER` - Number of parallel workers (default: 10)
- `--output [console|json|csv|all]` - Output format (default: console)
- `--save-to TEXT` - Custom storage location (S3 bucket, local path, or network share)
- `--cross-account-role TEXT` - Custom role name for cross-account access (default: OrganizationAccountAccessRole)
- `--org-admin-account-id TEXT` - Organization admin account ID (if different from current account)

## 🔍 Service Coverage

### 16 Core Services
1. **EC2** - 16 commands (13 individual checks)
2. **RDS** - 17 commands (14 individual checks)
3. **S3** - 14 commands (11 individual checks)
4. **IAM** - 13 commands (10 individual checks)
5. **EBS** - 12 commands (9 individual checks)
6. **Load Balancer** - 10 commands (7 individual checks)
7. **Security Groups** - 9 commands (6 individual checks)
8. **Lambda** - 8 commands (5 individual checks)
9. **EIP** - 7 commands (4 individual checks)
10. **CloudWatch** - 7 commands (4 individual checks)
11. **Backup** - 6 commands (3 individual checks)
12. **NAT Gateway** - 6 commands (3 individual checks)
13. **Snapshots** - 6 commands (3 individual checks)
14. **API Gateway** - 5 commands (2 individual checks)
15. **DynamoDB** - 5 commands (2 individual checks)
16. **Route53** - 5 commands (2 individual checks)

## 💡 Usage Examples

### Basic Usage
```bash
# Quick scan of all services (cost + security)
kosty audit

# Scan specific service (cost + security)
kosty ec2 audit

# Cost-only analysis
kosty s3 cost-audit

# Security-only analysis
kosty iam security-audit
kosty rds security-audit
kosty s3 security-audit
```

### Advanced Usage
```bash
# Organization-wide scan with custom parameters
kosty audit --organization --max-workers 20 --output json

# Multi-region scan
kosty audit --regions us-east-1,eu-west-1,ap-southeast-1 --max-workers 15

# Organization with multi-region
kosty ec2 audit --organization --regions us-east-1,eu-west-1

# Custom cross-account role
kosty audit --organization --cross-account-role MyCustomRole

# Separate org admin account
kosty audit --organization --org-admin-account-id 123456789012

# Combined custom role and admin account
kosty audit --organization --cross-account-role MyRole --org-admin-account-id 123456789012

# Enterprise storage workflows
kosty audit --organization --save-to s3://company-audits/monthly/
kosty ec2 audit --regions us-east-1,eu-west-1 --save-to \\\\nas\\aws-reports\\
kosty iam security-audit --organization --save-to /mnt/security/iam/

# Cost optimization checks
kosty ec2 check-oversized-instances --cpu-threshold 15 --regions us-east-1,eu-west-1 --save-to s3://cost-reports/
kosty s3 check-empty-buckets --organization --save-to /Volumes/shared/s3-audit/

# Security audit checks
kosty iam check-root-access-keys --organization --save-to \\\\security\\iam\\
kosty s3 check-public-read-access --regions us-east-1,eu-west-1 --save-to /mnt/reports/
kosty ec2 check-ssh-open --organization --regions us-east-1,eu-west-1 --save-to s3://security-audits/
```

### Output Formats

#### Console Output (Default)
```bash
kosty ec2 audit
# Displays formatted table with issues found
```

#### JSON Output
```bash
kosty ec2 audit --output json
# Generates structured JSON for programmatic use
```

#### CSV Output
```bash
kosty ec2 audit --output csv
# Creates CSV file for spreadsheet analysis
```

## 📊 Dashboard Usage

### Generating Reports for Dashboard
```bash
# Generate JSON report
kosty audit --output json > report.json

# Open dashboard
open dashboard/index.html
# Upload the JSON file in the dashboard
```

### Dashboard Features
- Interactive charts and graphs
- Filter by service, severity, type
- Export capabilities
- Mobile-responsive design

## 🛠️ Troubleshooting

### Common Issues

#### Permission Denied
```bash
# Error: Access Denied
# Solution: Check IAM permissions
aws sts get-caller-identity  # Verify credentials
```

#### No Resources Found
```bash
# Issue: Commands return no results
# Solution: Check region and credentials
kosty ec2 audit --region us-west-2  # Try different region
kosty ec2 audit --regions us-east-1,us-west-2,eu-west-1  # Try multiple regions
```

#### Organization Access Issues
```bash
# Error: Unable to assume role in member account
# Solution: Verify cross-account role setup
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/KostyRole --role-session-name test

# Error: AWSOrganizationsNotInUseException
# Solution: Use single account mode
kosty audit  # Remove --organization flag

# Error: Access denied to Organizations API
# Solution: Use org admin account
kosty audit --organization --org-admin-account-id 123456789012

# Error: Role not found
# Solution: Specify correct role name
kosty audit --organization --cross-account-role YourActualRoleName
```

#### Performance Issues
```bash
# Issue: Slow execution
# Solution: Adjust worker count
kosty audit --max-workers 5  # Reduce workers
kosty audit --max-workers 20 # Increase workers (if you have permissions)
```

### Rate Limiting
If you encounter AWS API rate limits:
```bash
# Reduce concurrent workers
kosty audit --max-workers 5

# Focus on specific services
kosty ec2 audit
kosty rds audit
```

## 📈 Performance Tips

### Optimization Strategies
1. **Use appropriate worker count** - Start with 10, adjust based on your AWS limits
2. **Target specific regions** - Use `--region` for single region or `--regions` for multiple regions
3. **Multi-region efficiency** - Workers are distributed across regions automatically
4. **Use service-specific commands** - Instead of full audit, run individual service audits
5. **Leverage organization mode efficiently** - Use higher worker counts for organization scans

### Best Practices
- Run during off-peak hours to avoid API throttling
- Use IAM roles instead of access keys when possible
- Start with cost-audit before running full audits
- Use JSON output for large-scale analysis

## 🤝 Support

### Getting Help
- Check this documentation first
- Review the [README.md](../README.md) for quick examples
- Open an issue on GitHub for bugs
- Start a discussion for feature requests

### Contributing
See the main README.md for contribution guidelines.

---

**💰 Happy cost optimizing with Kosty!**
