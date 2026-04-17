# 💰 Kosty - AWS Cost Optimization & Security Audit CLI Tool

<div align="center">

![Kosty Logo](https://img.shields.io/badge/💰-Kosty-blue?style=for-the-badge)
[![Python](https://img.shields.io/badge/Python-3.7+-blue?style=flat-square&logo=python)](https://python.org)
[![AWS](https://img.shields.io/badge/AWS-Compatible-orange?style=flat-square&logo=amazon-aws)](https://aws.amazon.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

> 💡 Need expert help optimizing your AWS infrastructure? [Professional consulting services available →](https://kosty.cloud?utm_source=github&utm_medium=readme-header)

**🚀 Identify AWS cost waste and security vulnerabilities across 23 core services with a single command**

*Save thousands of dollars monthly and improve security posture by finding unused resources, oversized instances, misconfigurations, and compliance issues*

*NEW: `kosty public-exposure` — Map your entire external attack surface in one command*

[🎯 Quick Start](#-quick-start) • [📖 Documentation](docs/DOCUMENTATION.md) • [🔧 Installation](#-installation) • [💡 Examples](#-examples)

## 📊 Visual Dashboard

**Not just CLI!** Kosty includes a beautiful, modern web dashboard to visualize your optimization results:

![Kosty Dashboard](dashboard/kosty_dashboard.png)

✨ **Premium Features**: Interactive charts, responsive design, real-time data visualization, and professional reporting.

</div>

---


## 🌟 Built by a Cloud Consultant, for Cloud Engineers

After years of AWS consulting , I kept finding the same costly patterns:
- Load Balancers with no targets  **10K$-30K$/year wasted**
- Orphaned EBS volumes: **$1,000-2,500/year**  
- Unused NAT Gateways, oversized instances, old snapshots,...

**Every. Single. Time.**

So I built Kosty - the tool I wish existed when I started consulting.


### What Kosty Does
- 🔍 Scans **23 core AWS services** in one command
- 💰 **Quantifies cost savings** with real dollar amounts (11 services)
- 📊 Finds **oversized instances** (EC2, RDS, Lambda)
- 🔐 Detects **security vulnerabilities** (public DBs, unencrypted storage, open ports)
- 🛡️ Identifies **compliance issues** (old access keys, public snapshots, weak configurations)
- 🛡️ **WAF & API Gateway hardening** (rate limiting, managed rules, authorization, logging)
- 🌐 **External attack surface mapping** — finds all publicly exposed resources and evaluates protections

**One command. Full audit. Real savings. Free forever.**

AWS costs and security risks can spiral out of control quickly. Kosty helps you:
- 🔍 **Discover** unused resources and security vulnerabilities across 23 core AWS services
- 💰 **Quantify** cost savings with real dollar amounts ($X/month calculations)
- 🔐 **Detect** security misconfigurations and compliance issues
- ⚡ **Optimize** with prioritized recommendations by financial impact
- 🏢 **Scale** across entire AWS Organizations with parallel processing
- 📊 Track ROI with detailed cost reporting


## 🎯 Quick Start

```bash
# Install Kosty via pip (recommended)
pip install kosty

# Or install from source
git clone https://github.com/kosty-cloud/kosty.git
cd kosty && ./install.sh

# 🚀 ONE COMMAND TO RULE THEM ALL - Comprehensive scan
kosty audit --output all

# Organization-wide comprehensive scan with reports
kosty audit --organization --max-workers 20 --output all

# Individual service scans
kosty ec2 audit --cpu-threshold 20
kosty rds audit
kosty s3 audit

# Cost and security audits separately
kosty ec2 cost-audit --cpu-threshold 20
kosty s3 security-audit
kosty iam security-audit

# Individual checks
kosty ec2 check-oversized-instances --cpu-threshold 20
kosty ec2 check-stopped-instances --days 7
kosty s3 check-empty-buckets
kosty rds check-public-databases

# 📊 View results in beautiful dashboard
open dashboard/index.html
```

## 🔧 Installation

### Prerequisites
- Python 3.7+
- AWS CLI configured with appropriate credentials

### Quick Install (Recommended)
```bash
pip install kosty
```

### Docker

Run Kosty in a secure, isolated container without installing Python dependencies.

```bash
# Pull the image
docker pull ghcr.io/kosty-cloud/kosty:latest

# Run audit with AWS credentials
docker run --rm \
  -v ~/.aws:/home/nonroot/.aws:ro \
  ghcr.io/kosty-cloud/kosty:latest audit

# Run with custom config file
docker run --rm \
  -v ~/.aws:/home/nonroot/.aws:ro \
  -v $(pwd)/kosty.yaml:/home/nonroot/kosty.yaml:ro \
  ghcr.io/kosty-cloud/kosty:latest audit --config-file kosty.yaml

# Save reports to local directory
docker run --rm \
  -v ~/.aws:/home/nonroot/.aws:ro \
  -v $(pwd)/reports:/home/nonroot/reports \
  ghcr.io/kosty-cloud/kosty:latest audit --output json
```

**Important**: The container runs as a non-root user for security. Mount your AWS credentials directory to `/home/nonroot/.aws` as read-only (`:ro`). Never mount credentials as read-write.

**Available tags:**
- `latest` - Latest stable release from main branch
- `1.x.x` - Specific version tags
- Multi-architecture support: AMD64 and ARM64

### Install from Source
```bash
git clone https://github.com/kosty-cloud/kosty.git
cd kosty
./install.sh
```

### Development Install
```bash
git clone https://github.com/kosty-cloud/kosty.git
cd kosty
pip install -e .
```

## 💡 Examples

### 🏆 High-Impact Optimizations with Cost Savings

```bash
# Find oversized EC2 instances (potential $280/month per m5.2xlarge)
kosty ec2 check-oversized-instances --cpu-threshold 20

# Find oversized RDS instances (potential $700/month per db.r5.4xlarge)
kosty rds check-oversized-instances --cpu-threshold 20

# Find over-provisioned Lambda functions (memory optimization savings)
kosty lambda check-over-provisioned-memory

# Find orphaned EBS volumes (potential $10/month per 100GB)
kosty ebs check-orphan-volumes

# Find unattached Elastic IPs (potential $3.60/month each)
kosty eip check-unattached-eips

# 💰 View total potential savings in dashboard
kosty audit --output json && open dashboard/index.html
```

### 🔍 Resource Discovery & Security Audits

```bash
# Storage optimization & security
kosty s3 check-empty-buckets
kosty s3 check-public-read-access
kosty s3 check-encryption-at-rest
kosty ebs check-orphan-volumes
kosty ebs check-unencrypted-orphan
kosty snapshots check-old-snapshots --days 30
kosty snapshots check-public-snapshots

# Database optimization & security
kosty rds check-oversized-instances --cpu-threshold 20
kosty rds check-public-databases
kosty rds check-unencrypted-storage
kosty dynamodb check-idle-tables

# Network optimization & security
kosty lb check-no-healthy-targets
kosty nat check-unused-gateways
kosty sg check-unused-groups
kosty sg check-overly-permissive

# Security & compliance checks
kosty ec2 check-ssh-open
kosty ec2 check-imdsv1
kosty ec2 check-unencrypted-ebs
kosty iam check-root-access-keys
kosty iam check-unused-roles
kosty iam check-old-access-keys
kosty iam check-root-mfa
kosty iam check-all-users-mfa
kosty iam check-passrole-permissions
kosty iam check-inline-policies

# WAF security audit
kosty waf audit
kosty waf check-no-rate-based-rule
kosty waf check-no-logging
kosty waf check-missing-managed-rules

# API Gateway security audit
kosty apigateway security-audit
kosty apigateway check-no-waf
kosty apigateway check-no-authorization
kosty apigateway check-no-throttling
kosty apigateway check-http-api-no-jwt

# S3 advanced security
kosty s3 check-no-object-lock
kosty s3 check-no-cross-region-replication

# RDS security
kosty rds check-no-auto-minor-upgrade
kosty rds check-no-performance-insights

# Foundational security checks
kosty cloudtrail audit
kosty vpc check-no-flow-logs
kosty guardduty check-not-enabled
kosty config check-not-enabled

# Secrets & AI
kosty secretsmanager check-unused-secrets
kosty secretsmanager check-no-rotation
kosty bedrock check-no-logging
kosty bedrock check-no-budget-limits
```

### 🌐 External Attack Surface Audit

```bash
# Map everything publicly exposed and evaluate protections
kosty public-exposure --output console

# Organization-wide attack surface mapping
kosty public-exposure --organization --output json

# Multi-region exposure scan
kosty public-exposure --regions us-east-1,eu-west-1 --output all
```

**What it scans (15 resource types):**
- ALB/NLB, EC2, S3, RDS, API Gateway, Lambda URLs, CloudFront
- OpenSearch, Redshift, EKS, ECR Public, SNS, SQS
- RDS & EBS Snapshots

**Findings classified as:**
- 🔴 Exposed & Unprotected — immediate action required
- 🟡 Exposed & Partially Protected — gaps to address
- 🟢 Exposed & Protected — all protections verified

### 🏢 Comprehensive Scanning

```bash
# 🎯 ULTIMATE COST AUDIT - All services, all checks
kosty audit --output all

# Organization-wide comprehensive scan (16 services)
kosty audit --organization --max-workers 20 --output json

# Multi-region comprehensive audit
kosty audit --regions us-east-1,eu-west-1,ap-southeast-1 --output csv

# Single region scan
kosty audit --region eu-west-1 --output json

# Quick console summary
kosty audit --output console

# Generate all report formats
kosty audit --organization --output all --max-workers 15

# 📊 Visualize results in dashboard
kosty audit --output json
open dashboard/index.html  # Upload the JSON file
```

## 🚀 Command Types

Kosty offers **3 types of commands** for maximum flexibility:

### 1. 🎯 **Complete Audits** - Full service analysis
```bash
kosty <service> audit           # Complete audit (cost + security)
kosty ec2 audit                 # All EC2 checks
kosty s3 audit                  # All S3 checks
```

### 2. 💰 **Targeted Audits** - Cost or security focus
```bash
kosty <service> cost-audit      # Cost optimization only
kosty <service> security-audit  # Security issues only

kosty ec2 cost-audit           # EC2 cost issues only
kosty s3 security-audit        # S3 security issues only
kosty iam security-audit       # IAM security issues only
```

### 3. 🔍 **Individual Checks** - Specific issue detection
```bash
kosty <service> check-<issue>   # Specific check

kosty ec2 check-oversized-instances
kosty ec2 check-stopped-instances
kosty s3 check-empty-buckets
kosty rds check-public-databases
kosty iam check-root-access-keys
```

### 4. 🌍 **Multi-Region & Organization** - Comprehensive scanning
```bash
# Multi-region scanning
kosty audit --regions us-east-1,eu-west-1,ap-southeast-1
kosty ec2 audit --regions us-east-1,eu-west-1

# Organization-wide with multi-region
kosty audit --organization --regions us-east-1,eu-west-1 --max-workers 20
kosty s3 check-public-read-access --organization --regions us-east-1,eu-west-1

# Custom cross-account role for organization scanning
kosty audit --organization --cross-account-role MyCustomRole

# Separate organizational admin account
kosty audit --organization --org-admin-account-id 123456789012

# Combined custom role and admin account
kosty audit --organization --cross-account-role MyRole --org-admin-account-id 123456789012
```

### 5. 🔄 **Multi-Profile Audits** - Run across all profiles in parallel
```bash
# Run audit on all profiles from config file
kosty audit --profiles --output all

# Control parallel execution (default: 3 profiles at once)
kosty audit --profiles --max-parallel-profiles 5

# Multi-profile with custom config file
kosty audit --config-file /path/to/config.yaml --profiles --output json

# Override settings for all profiles
kosty audit --profiles --max-workers 10 --output csv
```

**What happens:**
- Reads all profiles from your config file
- Runs audits in parallel (default: 3 at a time)
- Generates separate reports per profile: `output/kosty_audit_<profile>_<timestamp>.json`
- Creates summary report: `output/kosty_summary_<timestamp>.json`
- Continues on errors (failed profiles don't stop others)
- Shows aggregated totals across all profiles

---

## 💰 Cost Quantification Engine

### 💵 Services with Cost Calculations (11 Services)

Kosty provides **real monthly and annual savings estimates** for these services:

| Service | Cost Calculation | Example Savings |
|---------|------------------|----------------|
| **EBS** | Orphaned volumes by size & type | $10.00/month (100GB gp2) |
| **EC2** | Stopped instances by type | $280.32/month (m5.2xlarge) |
| **EIP** | Unattached Elastic IPs | $3.60/month (fixed rate) |
| **NAT Gateway** | Unused gateways | $32.85/month (per gateway) |
| **Load Balancer** | ALBs with no targets | $16.43/month (per ALB) |
| **S3** | Lifecycle optimization candidates | $2.30/month (100GB) |
| **Snapshots** | Old EBS snapshots | $5.00/month (100GB) |
| **Backup** | Empty AWS Backup vaults | $0.00/month (no storage) |
| **RDS** | Oversized instances (<20% CPU) | $700.80/month (db.r5.4xlarge) |
| **Lambda** | Over-provisioned memory (>512MB) | $0.68/month (optimization) |
| **DynamoDB** | Idle tables (low RCU/WCU) | Variable (on-demand savings) |

### 📈 Services with Audit Only (5 Services)

These services provide security and compliance audits without cost quantification:
- **IAM**: Security policies, unused roles, compliance
- **CloudWatch**: Log retention, unused alarms
- **Route53**: Unused hosted zones, DNS configuration
- **API Gateway**: Unused APIs, security configuration
- **Security Groups**: Unused groups, overly permissive rules

### ⚠️ Cost Calculation Disclaimer

**Important**: Cost estimates are based on AWS Pricing API and standard on-demand rates. **Actual costs may vary** due to:

- 💰 **Reserved Instance discounts** (up to 75% off)
- 💰 **Savings Plans** (up to 72% off)
- 💰 **Volume discounts** for high usage
- 🌍 **Regional pricing variations**
- 🏢 **Enterprise agreements** and custom pricing
- 📈 **Spot instance pricing** (up to 90% off)
- 🔄 **Free tier limits** and credits

**Use estimates for**: Relative comparison between issues, optimization prioritization, business case development, and ROI trend analysis.

**Verify actual costs** in your AWS billing dashboard before making decisions.

---

## 📊 Complete Service Coverage (23 Services)

### 🎯 Service Overview

| Category | Services | Key Checks |
|----------|----------|------------|
| **💻 Compute** | EC2, Lambda | Oversized instances, unused functions, IMDSv1+oversized combo |
| **🗄️ Storage** | S3, EBS, Snapshots | Empty buckets, orphaned volumes, old snapshots |
| **🗃️ Database** | RDS, DynamoDB | Idle databases, over-provisioned tables |
| **🌐 Network** | EIP, LB, NAT, SG, Route53, VPC | Unused resources, no healthy targets, flow logs |
| **🔐 Security** | IAM, WAFv2, GuardDuty | MFA, privilege escalation, rate limiting, threat detection |
| **📊 Management** | CloudWatch, Backup, CloudTrail, AWS Config | Logging, alarms, audit trail, drift detection |
| **🌐 Application** | API Gateway | WAF association, authorization, throttling, logging |
| **🤖 AI/ML** | Bedrock | Invocation logging, budget limits |
| **🔑 Secrets** | Secrets Manager | Unused secrets, rotation |

### 📋 Service Commands Summary

| Service | Total Commands | Audit Types | Individual Checks |
|---------|----------------|-------------|-------------------|
| **EC2** | 16 | 3 | 13 checks |
| **RDS** | 17 | 3 | 14 checks |
| **S3** | 14 | 3 | 11 checks |
| **IAM** | 22 | 3 | 16 checks |
| **EBS** | 12 | 3 | 9 checks |
| **LB** | 10 | 3 | 7 checks |
| **SG** | 9 | 3 | 6 checks |
| **WAFv2** | 8 | 3 | 5 checks |
| **API Gateway** | 11 | 3 | 8 checks |
| **Lambda** | 8 | 3 | 5 checks |
| **EIP** | 7 | 3 | 4 checks |
| **CloudWatch** | 7 | 3 | 4 checks |
| **Backup** | 6 | 3 | 3 checks |
| **NAT** | 6 | 3 | 3 checks |
| **Snapshots** | 6 | 3 | 3 checks |
| **API Gateway** | 5 | 3 | 2 checks |
| **DynamoDB** | 5 | 3 | 2 checks |
| **Route53** | 5 | 3 | 2 checks |

**📊 Total: 147 commands (1 global + 146 service commands)**

### 🔍 Top Individual Checks by Service

**EC2 (13 individual checks):**
- `check-oversized-instances` - Instances with low CPU utilization
- `check-stopped-instances` - Instances stopped for 7+ days
- `check-ssh-open` - SSH port open to 0.0.0.0/0
- `check-idle-instances` - Instances with <5% CPU usage

**S3 (11 individual checks):**
- `check-empty-buckets` - Buckets with no objects
- `check-public-read-access` - Buckets with public read access
- `check-encryption-at-rest` - Unencrypted buckets
- `check-lifecycle-policy` - Buckets needing lifecycle policies

**RDS (14 individual checks):**
- `check-public-databases` - Publicly accessible databases
- `check-oversized-instances` - Over-provisioned RDS instances
- `check-unused-read-replicas` - Unused read replicas
- `check-unencrypted-storage` - Unencrypted RDS storage

**IAM (16 individual checks):**
- `check-root-access-keys` - Root account access keys
- `check-root-mfa` - Root account MFA status
- `check-all-users-mfa` - Console users without MFA
- `check-unused-roles` - Roles unused for 90+ days
- `check-inactive-users` - Inactive users with active keys
- `check-wildcard-policies` - Policies with wildcard permissions
- `check-old-access-keys` - Access keys older than 90 days
- `check-unused-access-keys` - Active keys unused for 90+ days
- `check-passrole-permissions` - iam:PassRole with wildcard resource
- `check-inline-policies` - Inline policies on users/roles/groups
- `check-shared-lambda-roles` - Lambda functions sharing execution roles
- `check-multiple-active-keys` - Users with multiple active access keys
- `check-wildcard-assume-role` - sts:AssumeRole with wildcard resource
- `check-privilege-escalation` - Detect 21 privilege escalation patterns (use `--deep` for SimulatePrincipalPolicy confirmation)

**WAFv2 (6 individual checks):**
- `check-unassociated-acls` - Web ACLs not attached to any resource
- `check-missing-managed-rules` - Missing Core Rule Set, IP Reputation, SQLi, or Known Bad Inputs
- `check-no-rate-based-rule` - No DDoS/brute-force rate limiting
- `check-no-logging` - WAF logging disabled
- `check-default-count-action` - Critical rules set to Count instead of Block
- `check-no-bot-control` - No Bot Control rule group configured

**API Gateway (8 individual checks):**
- `check-unused-apis` - APIs with zero requests
- `check-no-waf` - Stages not protected by WAF
- `check-no-authorization` - Endpoints with AUTH_TYPE=NONE
- `check-no-logging` - Access/execution logging disabled
- `check-no-throttling` - No custom throttling (cost-bleeding risk)
- `check-private-api-no-policy` - Private APIs without resource policy
- `check-http-api-no-jwt` - HTTP APIs without JWT authorizer
- `check-custom-domain-no-tls12` - Custom domains not enforcing TLS 1.2
- `check-missing-request-validation` - Methods without request validation
- `check-cloudfront-bypass` - APIs behind CloudFront without resource policy restricting direct access

## 🎯 The Ultimate Command

```bash
# 🚀 ONE COMMAND TO AUDIT EVERYTHING
kosty audit

# Organization-wide comprehensive audit
kosty audit --organization --max-workers 20

# Generate all report formats
kosty audit --output all
```

**What `kosty audit` does:**
- Scans 23 core AWS services automatically
- Runs complete audits (cost + security) per service
- Generates comprehensive reports (JSON, CSV, Console)
- Prioritizes issues by severity and impact
- Scales across single account or entire organization

## 🚀 Features

### CLI + Web Dashboard
- Modular CLI architecture organized by AWS service
- Powerful command line interface for automation
- Modern React-based web dashboard with interactive charts
- Multiple report formats: Console, JSON, CSV, visual reports

### Comprehensive Analysis
- 23 core AWS services coverage
- Real dollar cost savings for 11 services
- One-command audit scans everything
- Multi-account organization support with configurable roles
- Multi-region scanning with `--regions`
- Multi-profile parallel execution with `--profiles`
- Flexible IAM with custom cross-account roles

### Performance & Usability
- Parallel processing with configurable workers
- Issues ranked by financial impact
- Read-only analysis, no resource modifications
- Executive-ready dashboards with cost totals
- Upfront permission checks with clear error messages

## 🔧 Configuration

Kosty supports YAML configuration files for persistent settings, profiles, and exclusions:

```bash
# Create config file from example
cp kosty.yaml.example kosty.yaml

# Use default profile
kosty audit

# Use specific profile
kosty audit --profile customer01

# Run all profiles in parallel
kosty audit --profiles --output all

# Use custom config file
kosty audit --config-file /path/to/config.yaml

# Override config with CLI args
kosty audit --profile customer01 --regions eu-west-1 --max-workers 30
```

### Features

- Multiple profiles for different environments
- Exclude specific accounts, regions, services, or ARNs
- Customize thresholds per profile
- AssumeRole with MFA support
- CLI args override config values

### Example Configuration

```yaml
exclude:
  accounts:
    - "123456789012"
  services:
    - "route53"
  arns:
    - "arn:aws:ec2:*:*:instance/i-protected*"

thresholds:
  ec2_cpu: 20
  rds_cpu: 20
  stopped_days: 7

default:
  organization: true
  regions:
    - us-east-1
    - eu-west-1
  max_workers: 20

profiles:
  customer01:
    regions: [us-east-1]
    # Option 1: AssumeRole (recommended for multi-account)
    role_arn: "arn:aws:iam::123456789012:role/MyRole"
    mfa_serial: "arn:aws:iam::123456789012:mfa/device"
  
  customer02:
    regions: [eu-west-1]
    # Option 2: AWS CLI profile (for local development)
    aws_profile: "customer02-prod"
  
  customer03:
    regions: [ap-southeast-1]
    # Option 3: Default credentials (env vars, instance role)
```

See [Configuration Guide](docs/CONFIGURATION.md) for complete documentation.

---

## 📖 Documentation

- [Complete Documentation](docs/DOCUMENTATION.md)
- [Configuration Guide](docs/CONFIGURATION.md)
- [Multi-Profile Guide](docs/MULTI_PROFILE_GUIDE.md) - NEW
- [AWS Credentials Setup](docs/DOCUMENTATION.md#aws-credentials-setup)
- [Organization Mode Setup](docs/DOCUMENTATION.md#organization-mode)
- [Cross-Account Role Configuration](docs/DOCUMENTATION.md#cross-account-roles)
- [Visual Dashboard](dashboard/README.md)
- [CLI Architecture](docs/CLI_ARCHITECTURE.md)
- [Release Notes](docs/RELEASE_NOTES.md)
- [Troubleshooting Guide](docs/DOCUMENTATION.md#troubleshooting)

## 🤝 Contributing

We welcome contributions:

1. **Report Issues** - Found a bug? [Open an issue](https://github.com/kosty-cloud/kosty/issues)
2. **Feature Requests** - Have an idea? [Start a discussion](https://github.com/kosty-cloud/kosty/discussions)
3. **Add Services** - Implement new AWS service checks
4. **Improve Docs** - Help make documentation better
5. **Star the Repo** - Show your support!

### Adding New Services

```python
# kosty/services/new_service_audit.py
import boto3
from typing import List, Dict, Any

class NewServiceAuditService:
    def __init__(self):
        self.cost_checks = ['check_unused_resources']
        self.security_checks = ['check_public_access']
    
    def audit(self, session: boto3.Session, region: str, **kwargs) -> List[Dict[str, Any]]:
        results = []
        results.extend(self.cost_audit(session, region, **kwargs))
        results.extend(self.security_audit(session, region, **kwargs))
        return results
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 💼 Professional Services

Kosty is free and open-source. For teams who want expert guidance to maximize results and safe implementation, I offer professional audits.

### What's Included

**Comprehensive AWS Cost & Security Audit**
- Full Kosty scan across all accounts and regions + manual architecture review
- Prioritized optimization roadmap ranked by ROI, effort, and risk
- Security vulnerability assessment (public databases, old IAM keys, overly permissive security groups)
- Implementation guidance and team training

**Typical Results:**
- €1K-30K/year in cost savings (most clients)
- Critical security gaps identified and resolved
- 2-7 day delivery depending on complexity
- Money-back guarantee if savings don't exceed the audit cost

### Pricing

| Tier | AWS Spend | Price | Timeline | What's Included |
|------|-----------|-------|----------|------------------|
| **Startup** | <€2K/mo | €500 | 2-3 days | Full scan, action plan, 30-min call, 2 weeks email support |
| **Growth** | €2-10K/mo | €1,500 | 3-5 days | Multi-account analysis, detailed roadmap, security report, 1-hour call, Slack support, 30-day follow-up |
| **Scale** | €10K+/mo | Custom | Custom | Everything in Growth + architecture deep-dive, team training, implementation support, quarterly check-ins |

### Why Work With Me?

- Built Kosty after 9 years of AWS consulting (seen the same waste patterns repeatedly)
- AWS specialist and FinOps
- Engineer-to-engineer approach: honest technical advice, no sales BS

### Get Started

**Free 30-minute assessment:** Book a no-commitment call to discuss your AWS setup and whether an audit makes sense.

📅 **Calendar:** https://calendly.com/consulting-kosty/30min  
📧 **Email:** yassir@kosty.cloud  
🌐 **Website:** https://kosty.cloud?utm_source=github&utm_medium=readme-section

---

## ⭐ Show Your Support

If Kosty helped you save money on AWS costs, please:

- ⭐ **Star this repository**
- 🐦 **Share on Twitter** with #AWSCostOptimization
- 💬 **Tell your colleagues** about cost optimization
- 🤝 **Contribute** to make it even better

---

<div align="center">

**💰 Save money. Optimize AWS. Scale efficiently.**

[🎯 Get Started](#-quick-start) • [📖 Documentation](docs/DOCUMENTATION.md) • [🤝 Contribute](#-contributing)

</div>
