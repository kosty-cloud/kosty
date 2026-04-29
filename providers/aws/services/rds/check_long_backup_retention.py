from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(check_id="aws-rds-006", service="RDS", provider="aws", finding_type=FindingType.COST, description="Find long backup retention on dev/test")
def check_long_backup_retention(session, region, **kwargs):
    """Flag excessive retention on non-production databases."""
    rds = session.client('rds', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        for db in rds.describe_db_instances()['DBInstances']:
            retention = db.get('BackupRetentionPeriod', 0)
            if retention <= 7:
                continue
            name = db['DBInstanceIdentifier'].lower()
            if any(k in name for k in ['dev', 'test', 'staging', 'demo', 'sandbox']):
                findings.append(Finding(
                    check_id="aws-rds-006", service="RDS",
                    resource_id=db['DBInstanceIdentifier'], region=region, account_id=account_id,
                    issue=f"Backup retention {retention} days on dev/test", severity=Severity.LOW,
                    finding_type=FindingType.COST, risk="Unnecessary backup storage cost", arn=db['DBInstanceArn'],
                ))
    except Exception:
        pass
    return findings
