from datetime import datetime, timedelta, timezone
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.core.config import resolve_threshold
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-lambda-004", service="Lambda", provider="aws", finding_type=FindingType.COST, description="Find over-provisioned Lambda memory")
def check_over_provisioned_memory(session: 'boto3.Session', region: str, days=30, **kwargs) -> List[Finding]:
    """Flag functions with high memory allocation but low duration — likely over-provisioned."""
    lam = session.client('lambda', region_name=region)
    cw = session.client('cloudwatch', region_name=region)
    account_id = get_account_id(session)
    memory_threshold = resolve_threshold(kwargs, 'lambda_memory', 'lambda_memory', 512)
    findings = []
    try:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days)
        paginator = lam.get_paginator('list_functions')
        for page in paginator.paginate():
            for func in page['Functions']:
                memory = func.get('MemorySize', 128)
                timeout = func.get('Timeout', 3)
                if memory <= memory_threshold:
                    continue
                try:
                    metrics = cw.get_metric_statistics(
                        Namespace='AWS/Lambda', MetricName='Duration',
                        Dimensions=[{'Name': 'FunctionName', 'Value': func['FunctionName']}],
                        StartTime=start, EndTime=end, Period=86400, Statistics=['Average']
                    )
                    if metrics['Datapoints']:
                        avg_ms = sum(dp['Average'] for dp in metrics['Datapoints']) / len(metrics['Datapoints'])
                        if avg_ms < (timeout * 1000 * 0.2):
                            findings.append(Finding(
                                check_id="aws-lambda-004", service="Lambda",
                                resource_id=func['FunctionName'], region=region, account_id=account_id,
                                issue=f"Over-provisioned ({memory}MB, avg {int(avg_ms)}ms vs {timeout}s timeout)",
                                severity=Severity.MEDIUM, finding_type=FindingType.COST,
                                risk="Paying for unused memory allocation",
                                arn=func['FunctionArn'],
                            ))
                except Exception as _exc:
                    handle_check_error(_exc)
                    continue
    except Exception as _exc:
        handle_check_error(_exc)
    return findings


@register_check(check_id="aws-lambda-005", service="Lambda", provider="aws", finding_type=FindingType.SECURITY, description="Find functions with timeout >5 minutes")
def check_long_timeout(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag functions with excessive timeout — consider ECS/Fargate for long-running tasks."""
    lam = session.client('lambda', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        paginator = lam.get_paginator('list_functions')
        for page in paginator.paginate():
            for func in page['Functions']:
                if func.get('Timeout', 3) > 300:
                    findings.append(Finding(
                        check_id="aws-lambda-005", service="Lambda",
                        resource_id=func['FunctionName'], region=region, account_id=account_id,
                        issue=f"Timeout >{func['Timeout']}s — consider ECS for long tasks",
                        severity=Severity.LOW, finding_type=FindingType.SECURITY,
                        risk="Anti-pattern — Lambda not designed for long-running workloads",
                        arn=func['FunctionArn'],
                    ))
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
