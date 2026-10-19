from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(
    check_id="aws-dynamodb-001",
    service="DynamoDB",
    provider="aws",
    finding_type=FindingType.COST,
    description="Find DynamoDB tables with near-zero consumed capacity",
)
def check_idle_tables(session: 'boto3.Session', region: str, days=7, **kwargs) -> List[Finding]:
    """Flag provisioned tables with minimal read/write activity."""
    from datetime import datetime, timedelta, timezone
    dynamodb = session.client('dynamodb', region_name=region)
    cw = session.client('cloudwatch', region_name=region)
    account_id = get_account_id(session)
    findings = []

    try:
        tables = dynamodb.list_tables().get('TableNames', [])
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days)

        for table_name in tables:
            try:
                table = dynamodb.describe_table(TableName=table_name)['Table']
                if table.get('BillingModeSummary', {}).get('BillingMode') == 'PAY_PER_REQUEST':
                    continue

                metrics = cw.get_metric_statistics(
                    Namespace='AWS/DynamoDB', MetricName='ConsumedReadCapacityUnits',
                    Dimensions=[{'Name': 'TableName', 'Value': table_name}],
                    StartTime=start, EndTime=end, Period=86400, Statistics=['Sum']
                )
                total_rcu = sum(dp['Sum'] for dp in metrics['Datapoints']) if metrics['Datapoints'] else 0

                if total_rcu < 100:
                    findings.append(Finding(
                        check_id="aws-dynamodb-001", service="DynamoDB",
                        resource_id=table_name, region=region, account_id=account_id,
                        issue=f"Idle provisioned table ({int(total_rcu)} RCU consumed in {days} days)",
                        severity=Severity.MEDIUM, finding_type=FindingType.COST,
                        risk="Consider switching to on-demand billing",
                        arn=table.get('TableArn', ''),
                    ))
            except Exception as _exc:
                handle_check_error(_exc)
                continue
    except Exception as _exc:
        handle_check_error(_exc)

    return findings
