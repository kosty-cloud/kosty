# 🚀 Kosty Release Notes

## Version 1.6.1 - Bug Fixes (2025-01-16)

### 🐛 Bug Fixes
- **Profile Configuration**: Fixed profile settings not being applied in service commands
  - `execute_service_command` now properly merges profile config with CLI args
  - Ensures profile settings (regions, role_arn, MFA, exclusions) are respected
  - CLI arguments still take priority over profile settings

- **Audit Command**: Fixed undefined variables in audit command
  - Resolved NameError for 'org' and 'admin_account' variables
  - JSON and CSV report generation now works correctly

### 🔧 Technical Details
- Added `merge_with_cli_args()` call in `execute_service_command`
- Consistent behavior between `audit` command and individual service commands
- Profile-based AWS session (AssumeRole/MFA) now works for all commands

---

## Version 1.6.0 - Tag-Based Resource Exclusion (2025-01-16)

### 🏷️ Major Feature: Tag-Based Exclusion Filtering
- **Resource Filtering by Tags**: Skip resources based on AWS tags before auditing
  - Filter resources BEFORE expensive API calls (CloudWatch metrics, etc.)
  - Support for exact match (key + value) or key-only matching
  - Works across all 16 services with tag support
  - Cumulative exclusions: profile tags add to global tags

### 🎯 Configuration Format
```yaml
exclude:
  tags:
    # Exact match (key + value)
    - key: "kosty_ignore"
      value: "true"
    
    # Key match (any value)
    - key: "Environment"
      value: "production"
    
    # Key exists (no value specified)
    - key: "Protected"
```

### 🚀 Usage Examples
```bash
# Tag your resources
aws ec2 create-tags --resources i-1234567890abcdef0 \
  --tags Key=kosty_ignore,Value=true

# Run audit - tagged resource will be skipped
kosty audit

# Per-profile tag exclusions
kosty audit --profile production
```

### 📊 Implementation Coverage
- **16 Services Updated**: ~160 methods modified across all services
- **Performance Optimized**: Resources filtered before expensive operations
- **Universal Support**: Works with EC2, S3, RDS, Lambda, EBS, and all other services

### 💡 Use Cases
- **Skip Production Resources**: Exclude production environment from audits
- **Protected Infrastructure**: Mark critical resources to skip
- **Temporary Resources**: Exclude temporary/testing resources
- **Customer-Specific**: Different exclusions per customer profile

### 🔧 Technical Implementation
- **tag_utils Module**: New utility module for tag filtering logic
- **ConfigManager Enhancement**: Tag exclusion support in configuration
- **Service Integration**: All services pass config_manager and filter by tags
- **Early Filtering**: Skip resources before CloudWatch/API calls

### 📖 Documentation Updates
- Updated `kosty.yaml.example` with tag exclusion examples
- Enhanced `CONFIGURATION.md` with comprehensive tag filtering guide
- Added examples for common use cases

---

## Version 1.5.1 - Multi-Profile Parallel Execution (2025-01-15)

### 🔄 Major Feature: Multi-Profile Audits
- **Parallel Profile Execution**: Run audits across all profiles simultaneously
  - New `--profiles` flag to execute all configured profiles
  - Parallel execution with configurable concurrency (default: 3 profiles at once)
  - Individual reports per profile with timestamp suffixes
  - Aggregated summary report across all profiles
  - Continue on errors - failed profiles don't stop others

### 📊 Enhanced Reporting
- **Profile-Specific Reports**: Each profile gets its own output file
  - Format: `output/kosty_audit_<profile>_<timestamp>.json`
  - Includes profile name, timestamp, and configuration metadata
  - Separate CSV reports per profile when using `--output csv`
  
- **Summary Report**: Consolidated view across all profiles
  - Total issues and savings aggregated
  - Per-profile breakdown with success/failure status
  - Error tracking for failed profiles
  - Format: `output/kosty_summary_<timestamp>.json`

### 🚀 Usage Examples
```bash
# Run all profiles in parallel
kosty audit --profiles --output all

# Control parallel execution
kosty audit --profiles --max-parallel-profiles 5

# Multi-profile with custom config
kosty audit --config-file /path/to/config.yaml --profiles

# Override settings for all profiles
kosty audit --profiles --max-workers 10 --output json
```

### 📈 Console Output
- Real-time progress tracking per profile
- Individual profile completion status with issue counts and savings
- Final summary table showing all profiles with totals
- Error reporting for failed profiles

### 🔧 Technical Implementation
- **MultiProfileRunner Class**: New module for parallel profile execution
- **ThreadPoolExecutor**: Efficient parallel processing with configurable workers
- **Profile Isolation**: Each profile runs independently with its own config
- **Error Resilience**: Exceptions in one profile don't affect others

### 💡 Use Cases
- **Multi-Customer Audits**: Run audits for all customers in one command
- **Environment Comparison**: Compare dev, staging, and production simultaneously
- **Regional Analysis**: Audit multiple regions with different configurations
- **Time Efficiency**: Reduce total audit time with parallel execution

---

## Version 1.4.0 - Cost Quantification Engine & Phase 2 Services (2025-11-02)

### 💰 Major Feature: Cost Quantification Engine
- **Financial ROI Calculations**: Transform Kosty from "linter" to "FinOps ROI tool"
  - Real monthly and annual savings calculations in USD
  - AWS Pricing API integration with intelligent fallbacks
  - 11 services now provide quantified cost savings
  - Dashboard displays total estimated savings prominently

### 🚀 Phase 2 Services - Complex Cost Analysis
- **RDS Cost Optimization**: Oversized database instance detection
  - CPU utilization analysis (<20% = oversized)
  - 50% savings estimation for rightsizing
  - Support for 10+ common instance types (db.t3.micro → db.r5.8xlarge)
  - Fallback pricing for API reliability

- **Lambda Cost Optimization**: Over-provisioned memory detection
  - Memory optimization analysis (>512MB threshold)
  - Free tier calculations (1M requests + 400K GB-seconds/month)
  - Request and duration cost components
  - 50% memory reduction savings estimation

- **DynamoDB Cost Optimization**: Idle table detection
  - Provisioned capacity analysis (RCU/WCU)
  - Free tier support (25 RCU + 25 WCU + 25 GB/month)
  - On-demand optimization recommendations (80% savings)
  - Low utilization threshold detection

### 💵 Enhanced Cost Calculation Coverage
**11 Services with Cost Quantification:**
- **Phase 1**: EBS, EC2, EIP, NAT Gateway, Load Balancer, S3, Snapshots, Backup
- **Phase 2**: RDS, Lambda, DynamoDB

**Services with Audit Only** (no cost calculation):
- IAM, CloudWatch, Route53, API Gateway, Security Groups

### 🎨 Dashboard Cost Integration
- **Total Estimated Savings Card**: Prominent green card showing monthly/annual savings
- **Individual Cost Display**: Each cost issue shows "$X.XX/month" in green
- **Cost Aggregation**: Service-level cost summaries and totals
- **ROI Calculator**: Visual impact representation with piggy bank icons

### 📊 Enhanced Reporting
- **Console Reports**: Cost savings included in summary with top issues by savings
- **JSON Reports**: `monthly_cost` and `cost_currency` fields added to cost findings
- **CSV Reports**: "Monthly Cost (USD)" and "Annual Cost (USD)" columns
- **All Formats**: Backward compatible with existing workflows

### ⚠️ Cost Calculation Disclaimer
**Important**: Cost estimates are based on AWS Pricing API and standard rates. Actual costs may vary due to:
- Reserved Instance discounts
- Savings Plans
- Volume discounts
- Regional pricing variations
- Custom enterprise agreements
- Spot instance pricing

Use estimates for relative comparison and optimization prioritization.

### 🔧 Technical Implementation
- **PricingService Class**: AWS Pricing API wrapper with intelligent caching
- **CostCalculator Class**: Service-specific cost calculation logic
- **Fallback Pricing**: Fixed prices for unreliable API services (EIP, S3, Snapshots)
- **Free Tier Support**: Accurate calculations for AWS Free Tier limits
- **Regional Pricing**: Support for 16+ AWS regions with location mapping

### 📈 Example Cost Savings
```bash
# Real examples from cost calculations:
RDS db.r5.4xlarge (5% CPU): $700.80/month savings
EC2 m5.2xlarge stopped: $280.32/month savings  
Lambda 3008MB→1024MB: $0.68/month savings
EBS 100GB orphaned: $10.00/month savings
EIP unattached: $3.60/month savings
```

---

## Version 1.3.8 - Enterprise Storage Support with Network Share Compatibility (2025-01-XX)

### 🌐 Enterprise Storage Features
- **Universal Storage Support**: Added `--save-to` parameter supporting multiple storage types
  - **S3 Buckets**: `kosty audit --save-to s3://my-bucket/reports/`
  - **Local Paths**: `kosty audit --save-to /home/user/reports/`
  - **Network Shares**: `kosty audit --save-to \\server\share\reports\` (Windows UNC)
  - **Network Mounts**: `kosty audit --save-to /mnt/nas/reports/` (Linux/macOS)

### 🔒 Advanced Storage Features
- **S3 Integration**: Full S3 support with enterprise-grade security
  - Automatic AES256 server-side encryption
  - Proper IAM permission validation
  - Clear error messages for access issues
  - Support for custom S3 paths and prefixes

- **Network Share Support**: Robust handling of enterprise network storage
  - Windows UNC path detection (`\\server\share` and `//server/share`)
  - Linux/macOS mount point detection (`/mnt/`, `/media/`, `/Volumes/`)
  - Network connectivity validation with timeouts
  - Automatic directory creation for network paths

### ⚡ Performance & Reliability
- **Upfront Validation**: Storage access validated before starting scans
  - Prevents wasted time on failed scans
  - Clear error messages with actionable suggestions
  - Test write operations to verify permissions

- **Timeout Management**: Smart timeout handling for network operations
  - 10-second timeout for connectivity validation
  - 30-second timeout for file write operations
  - Prevents hanging on unreachable network shares

### 🏢 Enterprise Workflow Integration
- **All 147 Commands**: Every service command supports `--save-to`
  - Individual services: `kosty ec2 check-oversized-instances --save-to \\nas\reports\`
  - Complete audits: `kosty audit --organization --save-to s3://audit-bucket/`
  - Targeted audits: `kosty s3 security-audit --save-to /mnt/shared/s3/`

- **Flexible File Management**: Intelligent file handling
  - Automatic directory creation for local and network paths
  - Descriptive filenames with timestamps
  - Support for both directory and specific file paths

### 🔧 Technical Improvements
- **StorageManager Class**: New centralized storage management
  - Async operations for better performance
  - Unified interface for all storage types
  - Comprehensive error handling and validation

- **Enhanced Reporter**: Updated reporting system
  - Async save methods for custom storage locations
  - Integration with StorageManager for all output formats
  - Maintains backward compatibility with existing workflows

### 📝 Usage Examples
```bash
# S3 storage with organization scan
kosty audit --organization --save-to s3://company-audits/2025/

# Network share for individual service
kosty ec2 audit --save-to \\fileserver\aws-reports\ec2\

# Linux NAS mount for security audit
kosty iam security-audit --save-to /mnt/nas/security/iam/

# macOS network volume
kosty s3 check-public-buckets --save-to /Volumes/SharedDrive/s3-audit/
```

---

## Version 1.3.3 - PyPI Distribution & Individual Service Cross-Account Support (2025-10-29)

### 📦 PyPI Distribution
- **Official PyPI Package**: Kosty is now available on PyPI for easy installation
  - Install with: `pip install kosty`
  - Automatic dependency management
  - No need to clone repository for basic usage
  - Simplified installation process for end users

### 🔧 Cross-Account Role Support for Individual Services
- **Fixed Individual Service Commands**: All service commands now support cross-account parameters
  - `--cross-account-role` and `--org-admin-account-id` work with all services
  - Enables independent service scanning in large organizations
  - Perfect for splitting long-running organization scans into smaller chunks
  - Example: `kosty ec2 audit --organization --cross-account-role MyRole`

### 📚 Documentation Updates
- Updated installation instructions to prioritize pip installation
- Enhanced examples with pip-based workflow
- Improved getting started guide for new users

---

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