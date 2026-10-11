from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(
    check_id="aws-elasticache-002",
    service="ElastiCache",
    provider="aws",
    finding_type=FindingType.SECURITY,
    description="Find Redis clusters without encryption in transit",
)
def check_no_encryption_in_transit(session, region, **kwargs):
    """Flag replication groups transmitting data in plaintext."""
    ec = session.client('elasticache', region_name=region)
    account_id = get_account_id(session)
    findings = []

    try:
        paginator = ec.get_paginator('describe_replication_groups')
        for page in paginator.paginate():
            for rg in page['ReplicationGroups']:
                if not rg.get('TransitEncryptionEnabled', False):
                    findings.append(Finding(
                        check_id="aws-elasticache-002", service="ElastiCache",
                        resource_id=rg['ReplicationGroupId'], region=region, account_id=account_id,
                        issue="Encryption in transit not enabled",
                        severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                        risk="Data between app and cache transmitted in plaintext",
                        arn=rg.get('ARN', ''),
                    ))
    except Exception:
        pass

    return findings
