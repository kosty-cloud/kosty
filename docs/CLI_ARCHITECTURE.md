# 🏗️ CLI Architecture - Modular Structure

## Overview

Kosty CLI has been refactored from a monolithic structure to a modular architecture for better maintainability and extensibility.

## Structure

```
kosty/cli/
├── __init__.py              # Main CLI entry point
├── __main__.py              # Module execution
├── utils.py                 # Common utilities
├── ec2_commands.py          # EC2 commands (16)
├── s3_commands.py           # S3 commands (14)
├── rds_commands.py          # RDS commands (17)
├── lambda_commands.py       # Lambda commands (8)
├── ebs_commands.py          # EBS commands (12)
├── iam_commands.py          # IAM commands (13)
├── eip_commands.py          # EIP commands (7)
├── lb_commands.py           # Load Balancer commands (10)
├── nat_commands.py          # NAT Gateway commands (6)
├── sg_commands.py           # Security Group commands (9)
├── cloudwatch_commands.py   # CloudWatch commands (7)
├── dynamodb_commands.py     # DynamoDB commands (5)
├── route53_commands.py      # Route53 commands (5)
├── apigateway_commands.py   # API Gateway commands (5)
├── backup_commands.py       # AWS Backup commands (6)
└── snapshots_commands.py    # EBS Snapshots commands (6)
```

## Benefits

- **Maintainability**: One file per AWS service (~100 lines each vs 2000+ monolithic)
- **Extensibility**: Easy to add new services
- **Collaboration**: Reduced Git conflicts
- **Testing**: Isolated unit tests per service

## Adding New Services

1. Create `service_commands.py`
2. Import in `__init__.py`
3. Add to CLI with `cli.add_command(service)`

## Common Utilities

- `common_options()`: Shared CLI options decorator
- `get_effective_params()`: Parameter resolution with priority
- `execute_service_command()`: Unified command execution