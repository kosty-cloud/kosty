# 📊 Kosty Service Coverage

> 30 AWS services, 180+ checks, organized by category.

## Compute

### EC2 (14 checks)
| Check | Type | Severity |
|-------|------|----------|
| `check-stopped-instances` | Cost | High |
| `check-idle-instances` | Cost | High |
| `check-oversized-instances` | Cost | High |
| `check-previous-generation` | Cost | Medium |
| `check-ssh-open` | Security | Critical |
| `check-rdp-open` | Security | Critical |
| `check-database-ports-open` | Security | Critical |
| `check-public-non-web` | Security | High |
| `check-old-ami` | Security | High |
| `check-imdsv1` | Security | Medium |
| `check-unencrypted-ebs` | Security | Medium |
| `check-no-recent-backup` | Security | Medium |
| `check-imdsv1-oversized` | Security | Critical |

### Lambda (5 checks)
| Check | Type | Severity |
|-------|------|----------|
| `check-unused-functions` | Cost | Low |
| `check-over-provisioned-memory` | Cost | Medium |
| `check-public-functions` | Security | High |
| `check-outdated-runtime` | Security | Medium |
| `check-long-timeout-functions` | Security | Low |

## Storage

### S3 (12 checks)
| Check | Type | Severity |
|-------|------|----------|
| `check-empty-buckets` | Cost | Low |
| `check-incomplete-uploads` | Cost | Medium |
| `check-lifecycle-policy` | Cost | High |
| `check-public-read-access` | Security | Critical |
| `check-public-write-access` | Security | Critical |
| `check-encryption-at-rest` | Security | Critical |
| `check-versioning-disabled` | Security | High |
| `check-access-logging` | Security | Medium |
| `check-bucket-policy-wildcards` | Security | High |
| `check-mfa-delete` | Security | Medium |
| `check-no-object-lock` | Security | Medium |
| `check-no-cross-region-replication` | Security | Low |
| `check-no-account-public-access-block` | Security | High |

### EBS (9 checks)
| Check | Type | Severity |
|-------|------|----------|
| `check-orphan-volumes` | Cost | High |
| `check-low-io-volumes` | Cost | Medium |
| `check-old-snapshots` | Cost | Low |
| `check-gp2-volumes` | Cost | Medium |
| `check-unencrypted-orphan` | Security | Critical |
| `check-unencrypted-in-use` | Security | High |
| `check-public-snapshots` | Security | Critical |
| `check-no-recent-snapshot` | Security | Medium |

### Snapshots (3 checks)
| Check | Type | Severity |
|-------|------|----------|
| `check-old-snapshots` | Cost | Low |
| `check-public-snapshots` | Security | Critical |
| `check-orphan-snapshots` | Cost | Medium |

## Database

### RDS (16 checks)
| Check | Type | Severity |
|-------|------|----------|
| `check-idle-instances` | Cost | High |
| `check-oversized-instances` | Cost | High |
| `check-unused-read-replicas` | Cost | High |
| `check-multi-az-non-prod` | Cost | Medium |
| `check-long-backup-retention` | Cost | Low |
| `check-gp2-storage` | Cost | Medium |
| `check-no-performance-insights` | Cost | Low |
| `check-publicly-accessible` | Security | Critical |
| `check-unencrypted-storage` | Security | Critical |
| `check-default-username` | Security | High |
| `check-wide-cidr-sg` | Security | High |
| `check-disabled-backups` | Security | High |
| `check-outdated-engine` | Security | Medium |
| `check-no-ssl-enforcement` | Security | Medium |
| `check-no-auto-minor-upgrade` | Security | Medium |
| `check-no-event-subscription` | Security | Medium |

### DynamoDB (2 checks)
| Check | Type | Severity |
|-------|------|----------|
| `check-idle-tables` | Cost | Medium |
| `check-on-demand-candidates` | Cost | Low |

## Network

### EIP (4 checks)
| Check | Type | Severity |
|-------|------|----------|
| `check-unattached-eips` | Cost | Medium |

### Load Balancer (7 checks)
| Check | Type | Severity |
|-------|------|----------|
| `check-no-healthy-targets` | Cost | High |

### NAT Gateway (3 checks)
| Check | Type | Severity |
|-------|------|----------|
| `check-unused-gateways` | Cost | High |

### Security Groups (6 checks)
| Check | Type | Severity |
|-------|------|----------|
| `check-unused-groups` | Cost | Low |
| `check-ssh-rdp-open` | Security | Critical |
| `check-database-ports-open` | Security | Critical |
| `check-all-ports-open` | Security | Critical |
| `check-complex-security-groups` | Security | Medium |
| `check-wide-cidr-rules` | Security | High |

### Route53 (2 checks)
| Check | Type | Severity |
|-------|------|----------|
| `check-unused-hosted-zones` | Cost | Low |

### VPC (2 checks)
| Check | Type | Severity |
|-------|------|----------|
| `check-no-flow-logs` | Security | High |
| `check-default-sg-open` | Security | Medium |

## Security & Identity

### IAM (18 checks)
| Check | Type | Severity |
|-------|------|----------|
| `check-root-access-keys` | Security | Critical |
| `check-root-mfa` | Security | Critical |
| `check-all-users-mfa` | Security | High |
| `check-admin-no-mfa` | Security | High |
| `check-old-access-keys` | Security | Critical |
| `check-unused-access-keys` | Security | High |
| `check-inactive-users` | Security | High |
| `check-multiple-active-keys` | Security | Medium |
| `check-wildcard-policies` | Security | High |
| `check-wildcard-assume-role` | Security | Critical |
| `check-passrole-permissions` | Security | Critical |
| `check-inline-policies` | Security | Medium |
| `check-shared-lambda-roles` | Security | Medium |
| `check-unused-roles` | Security | High/Critical |
| `check-weak-password-policy` | Security | Medium |
| `check-no-password-rotation` | Security | Medium |
| `check-cross-account-no-external-id` | Security | High |
| `check-privilege-escalation [--deep]` | Security | Critical |

### WAFv2 (6 checks)
| Check | Type | Severity |
|-------|------|----------|
| `check-unassociated-acls` | Security | High |
| `check-missing-managed-rules` | Security | High |
| `check-no-rate-based-rule` | Security | Critical |
| `check-no-logging` | Security | High |
| `check-default-count-action` | Security | High |
| `check-no-bot-control` | Security | Medium |

### GuardDuty (1 check)
| Check | Type | Severity |
|-------|------|----------|
| `check-not-enabled` | Security | High |

### KMS (1 check)
| Check | Type | Severity |
|-------|------|----------|
| `check-no-key-rotation` | Security | Medium |

## Management & Monitoring

### CloudWatch (4 checks)
| Check | Type | Severity |
|-------|------|----------|
| `check-log-retention` | Security | High |
| `check-unused-alarms` | Security | Low |
| `check-unused-custom-metrics` | Cost | Low |

### Backup (3 checks)
| Check | Type | Severity |
|-------|------|----------|
| `check-empty-vaults` | Cost | Low |

### CloudTrail (3 checks)
| Check | Type | Severity |
|-------|------|----------|
| `check-not-enabled` | Security | Critical |
| `check-no-log-validation` | Security | High |
| `check-no-encryption` | Security | Medium |

### AWS Config (1 check)
| Check | Type | Severity |
|-------|------|----------|
| `check-not-enabled` | Security | High |

## Application

### API Gateway (10 checks)
| Check | Type | Severity |
|-------|------|----------|
| `check-unused-apis` | Cost | Low |
| `check-no-waf` | Security | High |
| `check-no-authorization` | Security | High |
| `check-no-logging` | Security | Medium |
| `check-no-throttling` | Security | Medium |
| `check-private-api-no-policy` | Security | High |
| `check-http-api-no-jwt` | Security | High |
| `check-custom-domain-no-tls12` | Security | Medium |
| `check-missing-request-validation` | Security | Medium |
| `check-cloudfront-bypass` | Security | High |

## AI/ML

### Bedrock (2 checks)
| Check | Type | Severity |
|-------|------|----------|
| `check-no-logging` | Security | High |
| `check-no-budget-limits` | Cost | High |

## Secrets & Encryption

### Secrets Manager (2 checks)
| Check | Type | Severity |
|-------|------|----------|
| `check-unused-secrets` | Cost | Low |
| `check-no-rotation` | Security | Medium |

### ACM (1 check)
| Check | Type | Severity |
|-------|------|----------|
| `check-expiring-certificates` | Security | Medium-Critical |

### ElastiCache (2 checks)
| Check | Type | Severity |
|-------|------|----------|
| `check-no-encryption-at-rest` | Security | High |
| `check-no-encryption-in-transit` | Security | High |

### SNS (1 check)
| Check | Type | Severity |
|-------|------|----------|
| `check-no-encryption` | Security | Medium |

### SQS (1 check)
| Check | Type | Severity |
|-------|------|----------|
| `check-no-encryption` | Security | Medium |

## Containers & Patch Management

### ECS (1 check)
| Check | Type | Severity |
|-------|------|----------|
| `check-privileged-tasks` | Security | Critical |

### SSM (1 check)
| Check | Type | Severity |
|-------|------|----------|
| `check-non-compliant-patches` | Security | Medium-Critical |

---

## Public Exposure Audit

`kosty public-exposure` scans 15 resource types:

| Resource | Exposed if... | Protections Verified |
|----------|--------------|---------------------|
| ALB/NLB | internet-facing | WAF, HTTPS |
| EC2 | Public IP | SG web-only, IMDSv2 |
| S3 | Public ACL/policy | CloudFront, PublicAccessBlock |
| RDS | PubliclyAccessible | SG, Encryption |
| RDS Snapshots | restore=all | — |
| EBS Snapshots | public | — |
| API Gateway | public endpoint | WAF, Throttling, Auth |
| Lambda URLs | function URL active | Auth type, CORS |
| CloudFront | distribution active | WAF, HTTPS, TLS 1.2 |
| OpenSearch | no VPC | Access Policy, Encryption, HTTPS |
| Redshift | PubliclyAccessible | SG, Encryption |
| EKS | public API endpoint | Private endpoint, CIDR, Audit logging |
| ECR Public | public repo | — |
| SNS | wildcard policy | — |
| SQS | wildcard policy | — |
