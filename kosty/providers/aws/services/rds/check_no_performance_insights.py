from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(check_id="aws-rds-007", service="RDS", provider="aws", finding_type=FindingType.COST, description="Find instances without Performance Insights")
def check_no_performance_insights(session, region, **kwargs):
    """Flag databases with no query-level visibility."""
    rds = session.client('rds', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        for db in rds.describe_db_instances()['DBInstances']:
            if not db.get('PerformanceInsightsEnabled', False):
                findings.append(Finding(
                    check_id="aws-rds-007", service="RDS",
                    resource_id=db['DBInstanceIdentifier'], region=region, account_id=account_id,
                    issue="Performance Insights disabled", severity=Severity.LOW,
                    finding_type=FindingType.COST, risk="No visibility into query bottlenecks", arn=db['DBInstanceArn'],
                ))
    except Exception:
        pass
    return findings
