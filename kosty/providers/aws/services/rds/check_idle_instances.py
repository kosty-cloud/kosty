from datetime import datetime, timedelta, timezone
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.core.tag_utils import excluded_by_tags
from kosty.core.config import resolve_threshold
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-rds-001", service="RDS", provider="aws", finding_type=FindingType.COST, description="Find idle RDS instances (<5% CPU)")
def check_idle_instances(session: 'boto3.Session', region: str, cpu_threshold=5, **kwargs) -> List[Finding]:
    """Flag databases burning money with near-zero utilization."""
    rds = session.client('rds', region_name=region)
    cw = session.client('cloudwatch', region_name=region)
    account_id = get_account_id(session)
    days = resolve_threshold(kwargs, 'days', 'idle_days', 7)
    findings = []
    try:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days)
        for db in rds.describe_db_instances()['DBInstances']:
            if excluded_by_tags(db, kwargs):
                continue
            if db['DBInstanceStatus'] != 'available':
                continue
            try:
                metrics = cw.get_metric_statistics(
                    Namespace='AWS/RDS', MetricName='CPUUtilization',
                    Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db['DBInstanceIdentifier']}],
                    StartTime=start, EndTime=end, Period=3600, Statistics=['Average']
                )
                if metrics['Datapoints']:
                    avg = sum(dp['Average'] for dp in metrics['Datapoints']) / len(metrics['Datapoints'])
                    if avg < cpu_threshold:
                        findings.append(Finding(
                            check_id="aws-rds-001", service="RDS",
                            resource_id=db['DBInstanceIdentifier'], region=region, account_id=account_id,
                            issue=f"Idle ({round(avg, 1)}% CPU, {db['DBInstanceClass']})",
                            severity=Severity.HIGH, finding_type=FindingType.COST,
                            risk="$100-1000/mo wasted on idle database",
                            arn=db['DBInstanceArn'],
                        ))
            except Exception as _exc:
                handle_check_error(_exc)
                continue
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
