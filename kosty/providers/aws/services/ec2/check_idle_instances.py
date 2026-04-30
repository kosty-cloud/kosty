from datetime import datetime, timedelta
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(check_id="aws-ec2-002", service="EC2", provider="aws", finding_type=FindingType.COST, description="Find idle instances (<5% CPU)")
def check_idle_instances(session, region, days=7, cpu_threshold=5, **kwargs):
    """Flag running instances barely using any CPU."""
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
                                check_id="aws-ec2-002", service="EC2",
                                resource_id=inst['InstanceId'], region=region, account_id=account_id,
                                issue=f"Idle ({round(avg, 1)}% CPU over {days} days, {inst['InstanceType']})",
                                severity=Severity.HIGH, finding_type=FindingType.COST,
                                risk="80-95% of instance cost wasted",
                            ))
                except Exception:
                    continue
    except Exception:
        pass
    return findings
