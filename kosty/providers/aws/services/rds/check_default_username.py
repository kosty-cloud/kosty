from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.core.tag_utils import excluded_by_tags


@register_check(check_id="aws-rds-010", service="RDS", provider="aws", finding_type=FindingType.SECURITY, description="Find default master usernames")
def check_default_username(session, region, **kwargs):
    """Flag databases using predictable admin usernames."""
    rds = session.client('rds', region_name=region)
    account_id = get_account_id(session)
    findings = []
    defaults = ['admin', 'root', 'postgres', 'mysql', 'sa', 'master']
    try:
        for db in rds.describe_db_instances()['DBInstances']:
            if excluded_by_tags(db, kwargs):
                continue
            if db.get('MasterUsername', '').lower() in defaults:
                findings.append(Finding(
                    check_id="aws-rds-010", service="RDS",
                    resource_id=db['DBInstanceIdentifier'], region=region, account_id=account_id,
                    issue=f"Default username: {db['MasterUsername']}", severity=Severity.HIGH,
                    finding_type=FindingType.SECURITY, risk="First target for brute force", arn=db['DBInstanceArn'],
                ))
    except Exception:
        pass
    return findings
