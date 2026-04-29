from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(
    check_id="aws-elasticache-001",
    service="ElastiCache",
    provider="aws",
    finding_type=FindingType.SECURITY,
    description="Find Redis clusters without encryption at rest",
)
def check_no_encryption_at_rest(session, region, **kwargs):
    """Flag replication groups storing data unencrypted on disk."""
    ec = session.client('elasticache', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []

    try:
        paginator = ec.get_paginator('describe_replication_groups')
        for page in paginator.paginate():
            for rg in page['ReplicationGroups']:
                if not rg.get('AtRestEncryptionEnabled', False):
                    findings.append(Finding(
                        check_id="aws-elasticache-001", service="ElastiCache",
                        resource_id=rg['ReplicationGroupId'], region=region, account_id=account_id,
                        issue="Encryption at rest not enabled",
                        severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                        risk="Cached data readable if underlying storage is compromised",
                        arn=rg.get('ARN', ''),
                    ))
    except Exception:
        pass

    return findings
