from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.core.tag_utils import excluded_by_tags
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-rds-004", service="RDS", provider="aws", finding_type=FindingType.COST, description="Find Multi-AZ on dev/test")
def check_multi_az_non_prod(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag Multi-AZ on non-production — double cost for no benefit."""
    rds = session.client('rds', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        for db in rds.describe_db_instances()['DBInstances']:
            if excluded_by_tags(db, kwargs):
                continue
            if not db.get('MultiAZ'):
                continue
            name = db['DBInstanceIdentifier'].lower()
            if any(k in name for k in ['dev', 'test', 'staging', 'demo', 'sandbox']):
                findings.append(Finding(
                    check_id="aws-rds-004", service="RDS",
                    resource_id=db['DBInstanceIdentifier'], region=region, account_id=account_id,
                    issue="Multi-AZ on non-production", severity=Severity.MEDIUM, finding_type=FindingType.COST,
                    risk="100% cost overhead for dev/test HA", arn=db['DBInstanceArn'],
                ))
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
