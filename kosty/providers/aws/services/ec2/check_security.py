from datetime import datetime, timedelta
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(check_id="aws-ec2-010", service="EC2", provider="aws", finding_type=FindingType.SECURITY, description="Find instances using IMDSv1")
def check_imdsv1(session, region, **kwargs):
    """Flag instances vulnerable to SSRF-based credential theft (Capital One vector)."""
    ec2 = session.client('ec2', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        instances = ec2.describe_instances()
        for res in instances['Reservations']:
            for inst in res['Instances']:
                tokens = inst.get('MetadataOptions', {}).get('HttpTokens', 'optional')
                if tokens == 'optional':
                    findings.append(Finding(
                        check_id="aws-ec2-010", service="EC2",
                        resource_id=inst['InstanceId'], region=region, account_id=account_id,
                        issue=f"IMDSv1 enabled ({inst['InstanceType']})",
                        severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                        risk="SSRF attacks can steal instance credentials",
                    ))
    except Exception:
        pass
    return findings


@register_check(check_id="aws-ec2-011", service="EC2", provider="aws", finding_type=FindingType.SECURITY, description="Find instances with unencrypted EBS volumes")
def check_unencrypted_ebs(session, region, **kwargs):
    """Flag instances with at least one unencrypted attached volume."""
    ec2 = session.client('ec2', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        instances = ec2.describe_instances()
        for res in instances['Reservations']:
            for inst in res['Instances']:
                for bdm in inst.get('BlockDeviceMappings', []):
                    vol_id = bdm.get('Ebs', {}).get('VolumeId')
                    if vol_id:
                        try:
                            vol = ec2.describe_volumes(VolumeIds=[vol_id])['Volumes'][0]
                            if not vol.get('Encrypted', False):
                                findings.append(Finding(
                                    check_id="aws-ec2-011", service="EC2",
                                    resource_id=inst['InstanceId'], region=region, account_id=account_id,
                                    issue="Unencrypted EBS volume attached",
                                    severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                                    risk="Data exposure if storage compromised",
                                ))
                                break
                        except Exception:
                            continue
    except Exception:
        pass
    return findings


@register_check(check_id="aws-ec2-012", service="EC2", provider="aws", finding_type=FindingType.SECURITY, description="Find instances with no recent AMI backup")
def check_no_recent_backup(session, region, days=30, **kwargs):
    """Flag instances without a recent AMI — no recovery point available."""
    ec2 = session.client('ec2', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        cutoff = datetime.now() - timedelta(days=days)
        instances = ec2.describe_instances()
        for res in instances['Reservations']:
            for inst in res['Instances']:
                images = ec2.describe_images(
                    Owners=[account_id],
                    Filters=[{'Name': 'state', 'Values': ['available']}, {'Name': 'description', 'Values': [f'*{inst["InstanceId"]}*']}]
                )
                has_recent = any(
                    datetime.strptime(img['CreationDate'], '%Y-%m-%dT%H:%M:%S.%fZ') > cutoff
                    for img in images['Images']
                )
                if not has_recent:
                    findings.append(Finding(
                        check_id="aws-ec2-012", service="EC2",
                        resource_id=inst['InstanceId'], region=region, account_id=account_id,
                        issue=f"No AMI backup in {days}+ days",
                        severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                        risk="No recovery point available",
                    ))
    except Exception:
        pass
    return findings


@register_check(check_id="aws-ec2-013", service="EC2", provider="aws", finding_type=FindingType.SECURITY, description="Find instances that are both IMDSv1 and oversized")
def check_imdsv1_oversized(session, region, days=14, cpu_threshold=20, **kwargs):
    """Cross-reference: SSRF-vulnerable AND wasting money — highest remediation priority."""
    ec2 = session.client('ec2', region_name=region)
    cw = session.client('cloudwatch', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        end = datetime.utcnow()
        start = end - timedelta(days=days)
        instances = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
        for res in instances['Reservations']:
            for inst in res['Instances']:
                if inst.get('MetadataOptions', {}).get('HttpTokens', 'optional') != 'optional':
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
                            findings.append(Finding(
                                check_id="aws-ec2-013", service="EC2",
                                resource_id=inst['InstanceId'], region=region, account_id=account_id,
                                issue=f"IMDSv1 + Oversized ({round(avg, 1)}% CPU) — remediate first",
                                severity=Severity.CRITICAL, finding_type=FindingType.SECURITY,
                                risk="SSRF-vulnerable instance wasting money — highest priority",
                            ))
                except Exception:
                    continue
    except Exception:
        pass
    return findings
