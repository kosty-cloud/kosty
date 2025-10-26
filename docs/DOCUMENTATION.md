# 📖 Kosty Documentation

## 🎯 Overview

Kosty is a comprehensive AWS cost optimization CLI tool that helps you identify and eliminate waste across 16 core AWS services. With 147 total commands, Kosty provides both high-level audits and granular individual checks.

## 🔧 Installation

### Prerequisites
- Python 3.7 or higher
- AWS CLI configured with appropriate credentials
- boto3 library

### Quick Installation
```bash
git clone https://github.com/yassirkachri/kosty.git
cd kosty
./install.sh
```

### Manual Installation
```bash
pip install -r requirements.txt
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
- `--region TEXT` - AWS region to scan
- `--max-workers INTEGER` - Number of parallel workers (default: 10)
- `--output [console|json|csv]` - Output format (default: console)

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
# Quick scan of all services
kosty audit

# Scan specific service
kosty ec2 audit

# Cost-only analysis
kosty s3 cost-audit

# Security-only analysis
kosty iam security-audit
```

### Advanced Usage
```bash
# Organization-wide scan with custom parameters
kosty audit --organization --max-workers 20 --output json

# Multi-region scan
kosty ec2 audit --region eu-west-1 --organization

# Specific checks with thresholds
kosty ec2 check-oversized-instances --cpu-threshold 15
kosty sg check-complex-security-groups --rule-threshold 30
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
```

#### Organization Access Issues
```bash
# Error: Unable to assume role in member account
# Solution: Verify cross-account role setup
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT:role/KostyRole --role-session-name test
```

#### Performance Issues
```bash
# Issue: Slow execution
# Solution: Adjust worker count
kosty audit --max-workers 5  # Reduce workers
kosty audit --max-workers 20 # Increase workers (if you have permissions)
```

### Debug Mode
```bash
# Enable verbose logging
export KOSTY_DEBUG=1
kosty ec2 audit
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

## 🔧 Configuration

### Environment Variables
```bash
export KOSTY_DEFAULT_REGION=us-east-1
export KOSTY_DEFAULT_OUTPUT=json
export KOSTY_MAX_WORKERS=10
export KOSTY_DEBUG=0
```

### Config File (Optional)
Create `~/.kosty/config.yaml`:
```yaml
default_region: us-east-1
default_output: console
max_workers: 10
organization_mode: false
```

## 📈 Performance Tips

### Optimization Strategies
1. **Use appropriate worker count** - Start with 10, adjust based on your AWS limits
2. **Target specific regions** - Use `--region` to focus on active regions
3. **Use service-specific commands** - Instead of full audit, run individual service audits
4. **Leverage organization mode efficiently** - Use higher worker counts for organization scans

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