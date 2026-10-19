from datetime import datetime, timedelta, timezone
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.services._pricing import ec2_monthly
from kosty.core.tag_utils import excluded_by_tags
from kosty.core.config import resolve_threshold
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-ec2-003", service="EC2", provider="aws", finding_type=FindingType.COST, description="Find oversized instances (<20% CPU)")
def check_oversized_instances(session: 'boto3.Session', region: str, days=14, **kwargs) -> List[Finding]:
    """Flag instances consistently underutilizing their allocated compute."""
    ec2 = session.client('ec2', region_name=region)
    cw = session.client('cloudwatch', region_name=region)
    account_id = get_account_id(session)
    cpu_threshold = resolve_threshold(kwargs, 'cpu_threshold', 'ec2_cpu', 20)
    findings = []
    try:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days)
        instances = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
        for res in instances['Reservations']:
            for inst in res['Instances']:
                if excluded_by_tags(inst, kwargs):
                    continue
                try:
                    metrics = cw.get_metric_statistics(
                        Namespace='AWS/EC2', MetricName='CPUUtilization',
                        Dimensions=[{'Name': 'InstanceId', 'Value': inst['InstanceId']}],
                        StartTime=start, EndTime=end, Period=3600, Statistics=['Average']
                    )
                    if metrics['Datapoints']:
                        avg = sum(dp['Average'] for dp in metrics['Datapoints']) / len(metrics['Datapoints'])
                        if avg < cpu_threshold:
                            instance_type = inst['InstanceType']
                            # Downsizing to the next smaller type saves roughly 50% of the current cost
                            savings = round(ec2_monthly(instance_type) * 0.5, 2)
                            findings.append(Finding(
                                check_id="aws-ec2-003", service="EC2",
                                resource_id=inst['InstanceId'], region=region, account_id=account_id,
                                issue=f"Oversized ({round(avg, 1)}% CPU, {instance_type})",
                                severity=Severity.HIGH, finding_type=FindingType.COST,
                                risk="30-60% waste — downsize to next smaller type",
                                monthly_savings=savings,
                                details={'instance_type': instance_type, 'avg_cpu': round(avg, 1)},
                            ))
                except Exception as _exc:
                    handle_check_error(_exc)
                    continue
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
