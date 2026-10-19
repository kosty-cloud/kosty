from datetime import datetime, timedelta, timezone
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(
    check_id="aws-cloudwatch-003",
    service="CloudWatch",
    provider="aws",
    finding_type=FindingType.COST,
    description="Find unused custom metrics (no data in 30 days)",
)
def check_unused_custom_metrics(session: 'boto3.Session', region: str, days=30, max_metrics=50, **kwargs) -> List[Finding]:
    """Flag custom metrics with no datapoints — billed at $0.30/mo each."""
    cw = session.client('cloudwatch', region_name=region)
    account_id = get_account_id(session)
    findings = []

    config_manager = kwargs.get('config_manager')
    if config_manager:
        max_metrics = config_manager.get_threshold('max_metrics', max_metrics)

    checked = 0
    try:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days)
        paginator = cw.get_paginator('list_metrics')

        for page in paginator.paginate():
            for metric in page['Metrics']:
                if checked >= max_metrics:
                    break
                if metric['Namespace'].startswith('AWS/'):
                    continue
                checked += 1
                try:
                    stats = cw.get_metric_statistics(
                        Namespace=metric['Namespace'], MetricName=metric['MetricName'],
                        Dimensions=metric.get('Dimensions', []),
                        StartTime=start, EndTime=end, Period=86400, Statistics=['SampleCount']
                    )
                    if not stats['Datapoints']:
                        findings.append(Finding(
                            check_id="aws-cloudwatch-003", service="CloudWatch",
                            resource_id=f"{metric['Namespace']}/{metric['MetricName']}",
                            region=region, account_id=account_id,
                            issue=f"Custom metric with no data in {days} days",
                            severity=Severity.LOW, finding_type=FindingType.COST,
                            risk="$0.30/mo per unused custom metric",
                            monthly_savings=0.30,
                        ))
                except Exception as _exc:
                    handle_check_error(_exc)
                    continue
            if checked >= max_metrics:
                break
    except Exception as _exc:
        handle_check_error(_exc)

    return findings
