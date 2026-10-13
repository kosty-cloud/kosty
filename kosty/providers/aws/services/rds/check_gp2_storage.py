from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.core.tag_utils import excluded_by_tags


@register_check(check_id="aws-rds-005", service="RDS", provider="aws", finding_type=FindingType.COST, description="Find gp2 storage")
def check_gp2_storage(session, region, **kwargs):
    """Flag gp2 — gp3 is 20% cheaper."""
    rds = session.client('rds', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        for db in rds.describe_db_instances()['DBInstances']:
            if excluded_by_tags(db, kwargs):
                continue
            if db.get('StorageType') == 'gp2':
                findings.append(Finding(
                    check_id="aws-rds-005", service="RDS",
                    resource_id=db['DBInstanceIdentifier'], region=region, account_id=account_id,
                    issue=f"gp2 storage ({db.get('AllocatedStorage', 0)}GB)", severity=Severity.MEDIUM,
                    finding_type=FindingType.COST, risk="20% overpaying vs gp3", arn=db['DBInstanceArn'],
                ))
    except Exception:
        pass
    return findings
