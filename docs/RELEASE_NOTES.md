# 🚀 Kosty Release Notes

## Version 1.3.1 - Organization Pagination Fix (2025-10-29)

### 🐛 Critical Bug Fix
- **Organization Account Pagination**: Fixed issue where only the first 20 accounts were scanned in large organizations
  - Replaced direct `list_accounts()` call with `get_paginator('list_accounts')`
  - Now properly retrieves all accounts regardless of organization size
  - Maintains filtering of suspended accounts (`Status == 'ACTIVE'`)
  - Ensures complete coverage for organizations with 20+ accounts

### 🏢 Impact
- Organizations with more than 20 accounts now get full audit coverage
- No performance impact for smaller organizations
- Maintains existing async execution and error handling

---

## Version 1.3.0 - Cross-Account Role Configuration & Enhanced Error Handling (2025-10-29)

### 🔐 New Cross-Account Features
- **Configurable Cross-Account Roles**: Added `--cross-account-role` parameter to specify custom role names
  - Default remains `OrganizationAccountAccessRole` for backward compatibility
  - Example: `kosty audit --organization --cross-account-role MyCustomRole`
  - Addresses environments with different role naming conventions

- **Separate Organizational Admin Account**: Added `--org-admin-account-id` parameter
  - Supports scenarios where the current account lacks Organizations API access
  - Example: `kosty audit --organization --org-admin-account-id 123456789012`
  - Kosty first assumes a role in the specified admin account before listing organization accounts

### ⚡ Enhanced Error Handling
- **Upfront Organizations Validation**: Added pre-flight checks for Organizations API access
  - Fails fast with clear error messages instead of letting each service fail individually
  - Provides actionable suggestions for permission issues
  - Detects common scenarios: not in organization, insufficient permissions, role not found

### 🔧 Technical Improvements
- **Smart Permission Validation**: Validates access before starting comprehensive scans
- **Improved Error Messages**: Clear, actionable feedback for configuration issues
- **Better User Experience**: Immediate feedback on access problems with suggested solutions
- **Flexible IAM Support**: Works with various organizational structures and role configurations

### 📝 Documentation Updates
- Added comprehensive cross-account role configuration guide
- Enhanced troubleshooting section with common scenarios
- Updated examples for various organizational setups
- Added IAM policy examples for cross-account access

### 🐛 Bug Fixes
- Fixed CSV export errors with varying field structures across services
- Resolved "Unknown" resource name display issues in EBS and other services
- Fixed CloudWatch timezone comparison errors
- Improved resource name extraction from AWS tags

---

## Version 1.2.0 - Multi-Region Support & Modular CLI Architecture (2025-10-26)

### 🏗️ Architecture Improvements
- **Modular CLI Structure**: Refactored monolithic CLI (2000+ lines) into 19 organized files
  - One file per AWS service (~100 lines each) for better maintainability
  - Centralized common utilities in `utils.py` to reduce code duplication
  - Improved extensibility for adding new services and commands
  - Better collaboration with reduced Git conflicts

### 🌍 New Features
- **Multi-Region Support**: Added `--regions` parameter to scan multiple AWS regions simultaneously
  - Example: `kosty audit --regions us-east-1,eu-west-1,ap-southeast-1`
  - Workers are automatically distributed across regions for optimal performance
  - Compatible with all commands (audit, cost-audit, security-audit, individual checks)
  - Works with organization mode: `kosty audit --organization --regions us-east-1,eu-west-1`

### 📊 Dashboard Improvements
- **Enhanced Issue Navigation**: Added "View all issues" modal for services with 3+ issues
  - Modern, responsive design with grid layout
  - Click-through navigation: Dashboard → View All → Issue Details → Back to View All
  - Maintains context when navigating between issue details
- **Improved Data Compatibility**: Fixed dashboard parsing for mixed case field names
- **Better User Experience**: Smooth navigation flow with intuitive back buttons

### 🔧 Technical Improvements
- **CLI Maintainability**: Organized CLI commands by AWS service for better code organization
- **Standardized Output Format**: All services now output consistent lowercase field names (`type`, `severity`)
- **Performance Optimization**: Multi-region scanning with intelligent worker distribution
- **Code Quality**: Cleaned up field naming inconsistencies across all 16 services

### 📖 Documentation Updates
- Updated README.md with multi-region examples and usage patterns
- Enhanced DOCUMENTATION.md with comprehensive multi-region guidance
- Added troubleshooting section for multi-region scenarios

### 🐛 Bug Fixes
- Fixed dashboard chart rendering issues with mixed case JSON fields
- Resolved severity badge color display problems
- Corrected filter functionality for lowercase field names

---

## Version 1.1.0 - Dashboard & Organization Support (2025-10-25)

### 🎨 New Features
- **Visual Dashboard**: Modern React-based web dashboard with interactive charts
- **Organization Mode**: Scan entire AWS Organizations with `--organization` flag
- **Multiple Output Formats**: Console, JSON, CSV, and combined output with `--output all`

### 📊 Dashboard Features
- Interactive charts for service distribution, issue types, and severity levels
- Responsive design for desktop and mobile
- Issue filtering by service, type, and severity
- Detailed issue modals with comprehensive information
- Professional reporting capabilities

### 🏢 Organization Support
- Multi-account scanning across entire AWS Organizations
- Parallel processing with configurable worker counts
- Cross-account role assumption for secure access
- Consolidated reporting across all accounts

---

## Version 1.0.0 - Initial Release (2025-10-24)

### 🚀 Core Features
- **16 AWS Services**: Comprehensive coverage of core AWS infrastructure
- **147 Total Commands**: Complete audit, targeted audits, and individual checks
- **Cost Optimization**: Identify unused resources, oversized instances, and waste
- **Security Analysis**: Detect misconfigurations, public access, and vulnerabilities

### 🔍 Service Coverage
- **Compute**: EC2, Lambda
- **Storage**: S3, EBS, Snapshots  
- **Database**: RDS, DynamoDB
- **Network**: EIP, Load Balancer, NAT Gateway, Security Groups, Route53
- **Security**: IAM
- **Management**: CloudWatch, Backup
- **Application**: API Gateway

### ⚡ Performance Features
- Parallel processing with configurable workers
- Read-only operations for safe analysis
- Efficient API usage with intelligent throttling
- Comprehensive error handling and logging

### 📋 Command Structure
- Global audit command for all services
- Service-specific audit commands
- Individual check commands for granular analysis
- Flexible output formats and filtering options

---

## 🔮 Upcoming Features

### Version 1.3.0 (Planned)
- **Cost Estimation**: Actual dollar savings calculations
- **Remediation Scripts**: Automated fix suggestions and scripts
- **Custom Rules**: User-defined optimization rules
- **Integration APIs**: REST API for external tool integration

### Version 1.4.0 (Planned)
- **Additional Services**: EKS, ECS, ElastiCache, Redshift support
- **Advanced Analytics**: Trend analysis and historical comparisons
- **Team Collaboration**: Shared dashboards and reporting
- **Enterprise Features**: RBAC, audit trails, compliance reporting

---

## 🤝 Contributing

We welcome contributions! See our [Contributing Guide](CONTRIBUTING.md) for details on:
- Reporting bugs and feature requests
- Adding new service checks
- Improving documentation
- Code contributions and pull requests

## 📞 Support

- **Documentation**: [docs/DOCUMENTATION.md](docs/DOCUMENTATION.md)
- **Issues**: [GitHub Issues](https://github.com/yassirkachri/kosty/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yassirkachri/kosty/discussions)

---

**💰 Happy cost optimizing with Kosty!**