from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.core.tag_utils import excluded_by_tags


@register_check(check_id="aws-rds-009", service="RDS", provider="aws", finding_type=FindingType.SECURITY, description="Find unencrypted RDS storage")
def check_unencrypted_storage(session, region, **kwargs):
    """Flag databases storing data without encryption at rest."""
    rds = session.client('rds', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        for db in rds.describe_db_instances()['DBInstances']:
            if excluded_by_tags(db, kwargs):
                continue
            if not db.get('StorageEncrypted', False):
                findings.append(Finding(
                    check_id="aws-rds-009", service="RDS",
                    resource_id=db['DBInstanceIdentifier'], region=region, account_id=account_id,
                    issue="Storage not encrypted", severity=Severity.CRITICAL,
                    finding_type=FindingType.SECURITY, risk="Data breach if storage compromised", arn=db['DBInstanceArn'],
                ))
    except Exception:
        pass
    return findings
