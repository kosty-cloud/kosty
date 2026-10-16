from datetime import datetime, timedelta
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-apigateway-001", service="APIGateway", provider="aws", finding_type=FindingType.COST, description="Find APIs with zero requests")
def check_unused_apis(session: 'boto3.Session', region: str, days=30, **kwargs) -> List[Finding]:
    """Flag REST APIs generating no traffic — pure cost."""
    apigw = session.client('apigateway', region_name=region)
    cw = session.client('cloudwatch', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        end = datetime.utcnow()
        start = end - timedelta(days=days)
        for api in apigw.get_rest_apis().get('items', []):
            try:
                metrics = cw.get_metric_statistics(
                    Namespace='AWS/ApiGateway', MetricName='Count',
                    Dimensions=[{'Name': 'ApiName', 'Value': api['name']}],
                    StartTime=start, EndTime=end, Period=86400, Statistics=['Sum']
                )
                total = sum(dp['Sum'] for dp in metrics['Datapoints']) if metrics['Datapoints'] else 0
                if total == 0:
                    findings.append(Finding(
                        check_id="aws-apigateway-001", service="APIGateway",
                        resource_id=api['name'], region=region, account_id=account_id,
                        issue=f"API unused (0 requests in {days} days)",
                        severity=Severity.LOW, finding_type=FindingType.COST,
                        risk="$3.50/mo per idle API",
                    ))
            except Exception as _exc:
                handle_check_error(_exc)
                continue
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
