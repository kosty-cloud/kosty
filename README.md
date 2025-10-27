# 💰 Kosty - AWS Cost Optimization CLI Tool

<div align="center">

![Kosty Logo](https://img.shields.io/badge/💰-Kosty-blue?style=for-the-badge)
[![Python](https://img.shields.io/badge/Python-3.7+-blue?style=flat-square&logo=python)](https://python.org)
[![AWS](https://img.shields.io/badge/AWS-Compatible-orange?style=flat-square&logo=amazon-aws)](https://aws.amazon.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

**🚀 Identify and eliminate AWS cost waste across 16 core services with a single command**

*Save thousands of dollars monthly by finding unused resources, oversized instances, and optimization opportunities*

[🎯 Quick Start](#-quick-start) • [📖 Documentation](docs/DOCUMENTATION.md) • [🔧 Installation](#-installation) • [💡 Examples](#-examples)

## 📊 Visual Dashboard

**Not just CLI!** Kosty includes a beautiful, modern web dashboard to visualize your optimization results:

![Kosty Dashboard](dashboard/kosty_dashboard.png)

✨ **Premium Features**: Interactive charts, responsive design, real-time data visualization, and professional reporting.

</div>

---


## 🌟 Built by a Cloud Consultant, for Cloud Engineers

After years of AWS consulting , I kept finding the same costly patterns:
- 70 Load Balancers with no targets at one client: **$25,000/year wasted**
- Orphaned EBS volumes: **$2,500/year**  
- Unused NAT Gateways, oversized instances, old snapshots,...

**Every. Single. Time.**

So I built Kosty - the tool I wish existed when I started consulting.


### What Kosty Does
- 🔍 Scans **16 core AWS services** in one command
- 💰 Identifies **orphaned resources** (instant savings)
- 📊 Finds **oversized instances** (EC2, RDS, Lambda)
- 🔐 Detects **security issues** (public DBs, old IAM keys)

**One command. Full audit. Free forever.**

AWS costs can spiral out of control quickly. Kosty helps you:
- 🔍 **Discover** unused resources across 16 core AWS services
- 🔍 **Identify** oversized and idle resources efficiently
- ⚡ **Optimize** with prioritized recommendations
- 🏢 **Scale** across entire AWS Organizations with parallel processing
- 📊 **Track** issues with comprehensive reporting


## 🎯 Quick Start

```bash
# Install Kosty
git clone https://github.com/yassirkachri/kosty.git
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
- boto3 library

### Quick Install
```bash
git clone https://github.com/yassirkachri/kosty.git
cd kosty
./install.sh
```

### Manual Install
```bash
pip install -r requirements.txt
pip install -e .
```

## 💡 Examples

### 🏆 High-Impact Optimizations

```bash
# Find oversized EC2 instances
kosty ec2 check-oversized-instances --cpu-threshold 20

# Find unused RDS read replicas
kosty rds check-unused-read-replicas

# Find over-provisioned Lambda functions
kosty lambda check-over-provisioned-memory

# Find orphaned EBS volumes
kosty ebs check-orphan-volumes

# Find unattached Elastic IPs
kosty eip check-unattached-eips
```

### 🔍 Resource Discovery

```bash
# Storage optimization
kosty s3 check-empty-buckets
kosty ebs check-orphan-volumes
kosty snapshots check-old-snapshots --days 30

# Database optimization  
kosty rds check-oversized-instances --cpu-threshold 20
kosty dynamodb check-idle-tables

# Network optimization
kosty lb check-no-healthy-targets
kosty nat check-unused-gateways
kosty sg check-unused-groups

# Security checks
kosty ec2 check-ssh-open
kosty rds check-public-databases
kosty s3 check-public-read-access
kosty iam check-root-access-keys
```

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
```

---

## 📊 Complete Service Coverage (16 Services)

### 🎯 Service Overview

| Category | Services | Key Checks |
|----------|----------|------------|
| **💻 Compute** | EC2, Lambda | Oversized instances, unused functions |
| **🗄️ Storage** | S3, EBS, Snapshots | Empty buckets, orphaned volumes, old snapshots |
| **🗃️ Database** | RDS, DynamoDB | Idle databases, over-provisioned tables |
| **🌐 Network** | EIP, LB, NAT, SG, Route53 | Unused resources, no healthy targets |
| **🔐 Security** | IAM | Unused roles, old access keys, inactive users |
| **📊 Management** | CloudWatch, Backup | Unused alarms, expensive logs, empty vaults |
| **🌐 Application** | API Gateway | Unused APIs, expensive configurations |

### 📋 Service Commands Summary

| Service | Total Commands | Audit Types | Individual Checks |
|---------|----------------|-------------|-------------------|
| **EC2** | 16 | 3 | 13 checks |
| **RDS** | 17 | 3 | 14 checks |
| **S3** | 14 | 3 | 11 checks |
| **IAM** | 13 | 3 | 10 checks |
| **EBS** | 12 | 3 | 9 checks |
| **LB** | 10 | 3 | 7 checks |
| **SG** | 9 | 3 | 6 checks |
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

**IAM (10 individual checks):**
- `check-root-access-keys` - Root account access keys
- `check-unused-roles` - Roles unused for 90+ days
- `check-inactive-users` - Inactive users with active keys
- `check-wildcard-policies` - Policies with wildcard permissions

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
- ✅ **Scans 16 core AWS services** automatically
- ✅ **Runs complete audits** (cost + security) per service
- ✅ **Generates comprehensive reports** (JSON, CSV, Console)
- ✅ **Prioritizes issues** by severity and impact
- ✅ **Scales across** single account or entire organization

## 🚀 Features

### 💻 **CLI + Web Dashboard**
- ✅ **Modular CLI Architecture** - Organized by AWS service for maintainability
- ✅ **Command Line Interface** - Powerful CLI for automation and scripting
- ✅ **Visual Web Dashboard** - Modern React-based interface with interactive charts
- ✅ **Multiple Report Formats** - Console, JSON, CSV outputs + visual reports

### 🔍 **Comprehensive Analysis**
- ✅ **16 Core AWS Services** - Essential infrastructure coverage
- ✅ **One-Command Audit** - `kosty audit` scans everything
- ✅ **Organization Support** - Multi-account scanning
- ✅ **Multi-Region** - Scan across multiple AWS regions simultaneously with `--regions`

### ⚡ **Performance & Usability**
- ✅ **Parallel Processing** - High-performance with configurable workers
- ✅ **Issue Tracking** - Comprehensive categorization and prioritization
- ✅ **Safe Operations** - Read-only analysis, no resource modifications
- ✅ **Professional Reporting** - Executive-ready dashboards and reports

## 📖 Documentation

- [📋 Complete Documentation](docs/DOCUMENTATION.md)
- [🔧 AWS Credentials Setup](docs/DOCUMENTATION.md#aws-credentials-setup)
- [🏢 Organization Mode Setup](docs/DOCUMENTATION.md#organization-mode)
- [📊 Visual Dashboard](dashboard/README.md)
- [🏗️ CLI Architecture](docs/CLI_ARCHITECTURE.md)
- [📝 Release Notes](docs/RELEASE_NOTES.md)
- [🛠️ Troubleshooting Guide](docs/DOCUMENTATION.md#troubleshooting)

## 🤝 Contributing

We welcome contributions! Here's how you can help:

1. **🐛 Report Issues** - Found a bug? [Open an issue](https://github.com/yassirkachri/kosty/issues)
2. **💡 Feature Requests** - Have an idea? [Start a discussion](https://github.com/yassirkachri/kosty/discussions)
3. **🔧 Add Services** - Implement new AWS service checks
4. **📖 Improve Docs** - Help make documentation better
5. **⭐ Star the Repo** - Show your support!

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