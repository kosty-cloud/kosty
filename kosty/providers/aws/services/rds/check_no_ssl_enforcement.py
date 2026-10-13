from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.core.tag_utils import excluded_by_tags


@register_check(check_id="aws-rds-016", service="RDS", provider="aws", finding_type=FindingType.SECURITY, description="Find databases without SSL enforcement")
def check_no_ssl_enforcement(session, region, **kwargs):
    """Flag databases potentially accepting unencrypted connections."""
    rds = session.client('rds', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        for db in rds.describe_db_instances()['DBInstances']:
            if excluded_by_tags(db, kwargs):
                continue
            findings.append(Finding(
                check_id="aws-rds-016", service="RDS",
                resource_id=db['DBInstanceIdentifier'], region=region, account_id=account_id,
                issue="SSL/TLS enforcement not verified", severity=Severity.MEDIUM,
                finding_type=FindingType.SECURITY, risk="Man-in-the-middle attacks on DB connections", arn=db['DBInstanceArn'],
            ))
    except Exception:
        pass
    return findings
