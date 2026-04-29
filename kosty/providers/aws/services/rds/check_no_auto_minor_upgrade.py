from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(check_id="aws-rds-014", service="RDS", provider="aws", finding_type=FindingType.SECURITY, description="Find instances without auto minor version upgrade")
def check_no_auto_minor_upgrade(session, region, **kwargs):
    """Flag databases missing automatic security patches."""
    rds = session.client('rds', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        for db in rds.describe_db_instances()['DBInstances']:
            if not db.get('AutoMinorVersionUpgrade', True):
                findings.append(Finding(
                    check_id="aws-rds-014", service="RDS",
                    resource_id=db['DBInstanceIdentifier'], region=region, account_id=account_id,
                    issue="Auto minor version upgrade disabled", severity=Severity.MEDIUM,
                    finding_type=FindingType.SECURITY, risk="Missing security patches", arn=db['DBInstanceArn'],
                ))
    except Exception:
        pass
    return findings
