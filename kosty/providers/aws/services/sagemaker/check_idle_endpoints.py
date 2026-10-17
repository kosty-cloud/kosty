from datetime import datetime, timedelta
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-sagemaker-001", service="SageMaker", provider="aws", finding_type=FindingType.COST, description="Find idle SageMaker endpoints (0 invocations)")
def check_idle_endpoints(session: 'boto3.Session', region: str, days=7, **kwargs) -> List[Finding]:
    """Flag GPU endpoints running 24/7 with zero traffic."""
    sm = session.client('sagemaker', region_name=region)
    cw = session.client('cloudwatch', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        end = datetime.utcnow()
        start = end - timedelta(days=days)
        for ep in sm.list_endpoints(StatusEquals='InService').get('Endpoints', []):
            try:
                metrics = cw.get_metric_statistics(
                    Namespace='AWS/SageMaker', MetricName='Invocations',
                    Dimensions=[{'Name': 'EndpointName', 'Value': ep['EndpointName']}],
                    StartTime=start, EndTime=end, Period=86400, Statistics=['Sum']
                )
                total = sum(dp['Sum'] for dp in metrics['Datapoints']) if metrics['Datapoints'] else 0
                if total == 0:
                    detail = sm.describe_endpoint(EndpointName=ep['EndpointName'])
                    variants = detail.get('ProductionVariants', [])
                    itype = variants[0].get('CurrentInstanceType', 'unknown') if variants else 'unknown'
                    findings.append(Finding(
                        check_id="aws-sagemaker-001", service="SageMaker",
                        resource_id=ep['EndpointName'], region=region, account_id=account_id,
                        issue=f"Idle endpoint ({itype}, 0 invocations in {days}d)",
                        severity=Severity.CRITICAL, finding_type=FindingType.COST,
                        risk=f"GPU running 24/7 for nothing — $500-5000/mo",
                        arn=ep.get('EndpointArn', ''),
                    ))
            except Exception as _exc:
                handle_check_error(_exc)
                continue
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
