from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(check_id="aws-rds-004", service="RDS", provider="aws", finding_type=FindingType.COST, description="Find Multi-AZ on dev/test")
def check_multi_az_non_prod(session, region, **kwargs):
    """Flag Multi-AZ on non-production — double cost for no benefit."""
    rds = session.client('rds', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        for db in rds.describe_db_instances()['DBInstances']:
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
    except Exception:
        pass
    return findings
