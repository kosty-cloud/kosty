from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.core.tag_utils import excluded_by_tags
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-rds-006", service="RDS", provider="aws", finding_type=FindingType.COST, description="Find long backup retention on dev/test")
def check_long_backup_retention(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag excessive retention on non-production databases."""
    rds = session.client('rds', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        for db in rds.describe_db_instances()['DBInstances']:
            if excluded_by_tags(db, kwargs):
                continue
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
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
