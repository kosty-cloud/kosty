from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.core.tag_utils import excluded_by_tags


@register_check(check_id="aws-rds-012", service="RDS", provider="aws", finding_type=FindingType.SECURITY, description="Find databases with backups disabled")
def check_disabled_backups(session, region, **kwargs):
    """Flag databases with retention=0 — no recovery possible."""
    rds = session.client('rds', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        for db in rds.describe_db_instances()['DBInstances']:
            if excluded_by_tags(db, kwargs):
                continue
            if db.get('BackupRetentionPeriod', 0) == 0:
                findings.append(Finding(
                    check_id="aws-rds-012", service="RDS",
                    resource_id=db['DBInstanceIdentifier'], region=region, account_id=account_id,
                    issue="Automated backups disabled", severity=Severity.HIGH,
                    finding_type=FindingType.SECURITY, risk="Data loss — no recovery point", arn=db['DBInstanceArn'],
                ))
    except Exception:
        pass
    return findings
