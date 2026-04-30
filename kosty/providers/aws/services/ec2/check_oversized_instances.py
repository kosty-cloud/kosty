from datetime import datetime, timedelta
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(check_id="aws-ec2-003", service="EC2", provider="aws", finding_type=FindingType.COST, description="Find oversized instances (<20% CPU)")
def check_oversized_instances(session, region, days=14, cpu_threshold=20, **kwargs):
    """Flag instances consistently underutilizing their allocated compute."""
    ec2 = session.client('ec2', region_name=region)
    cw = session.client('cloudwatch', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        end = datetime.utcnow()
        start = end - timedelta(days=days)
        instances = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
        for res in instances['Reservations']:
            for inst in res['Instances']:
                try:
                    metrics = cw.get_metric_statistics(
                        Namespace='AWS/EC2', MetricName='CPUUtilization',
                        Dimensions=[{'Name': 'InstanceId', 'Value': inst['InstanceId']}],
                        StartTime=start, EndTime=end, Period=3600, Statistics=['Average']
                    )
                    if metrics['Datapoints']:
                        avg = sum(dp['Average'] for dp in metrics['Datapoints']) / len(metrics['Datapoints'])
                        if avg < cpu_threshold:
                            findings.append(Finding(
                                check_id="aws-ec2-003", service="EC2",
                                resource_id=inst['InstanceId'], region=region, account_id=account_id,
                                issue=f"Oversized ({round(avg, 1)}% CPU, {inst['InstanceType']})",
                                severity=Severity.HIGH, finding_type=FindingType.COST,
                                risk="30-60% waste — downsize to next smaller type",
                            ))
                except Exception:
                    continue
    except Exception:
        pass
    return findings
