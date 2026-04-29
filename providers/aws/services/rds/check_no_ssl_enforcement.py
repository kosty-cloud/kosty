from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(check_id="aws-rds-016", service="RDS", provider="aws", finding_type=FindingType.SECURITY, description="Find databases without SSL enforcement")
def check_no_ssl_enforcement(session, region, **kwargs):
    """Flag databases potentially accepting unencrypted connections."""
    rds = session.client('rds', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        for db in rds.describe_db_instances()['DBInstances']:
            findings.append(Finding(
                check_id="aws-rds-016", service="RDS",
                resource_id=db['DBInstanceIdentifier'], region=region, account_id=account_id,
                issue="SSL/TLS enforcement not verified", severity=Severity.MEDIUM,
                finding_type=FindingType.SECURITY, risk="Man-in-the-middle attacks on DB connections", arn=db['DBInstanceArn'],
            ))
    except Exception:
        pass
    return findings
