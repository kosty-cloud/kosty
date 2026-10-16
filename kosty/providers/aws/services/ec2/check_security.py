from datetime import datetime, timedelta
from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.core.tag_utils import excluded_by_tags
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-ec2-010", service="EC2", provider="aws", finding_type=FindingType.SECURITY, description="Find instances using IMDSv1")
def check_imdsv1(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag instances vulnerable to SSRF-based credential theft (Capital One vector)."""
    ec2 = session.client('ec2', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        instances = ec2.describe_instances()
        for res in instances['Reservations']:
            for inst in res['Instances']:
                if excluded_by_tags(inst, kwargs):
                    continue
                tokens = inst.get('MetadataOptions', {}).get('HttpTokens', 'optional')
                if tokens == 'optional':
                    findings.append(Finding(
                        check_id="aws-ec2-010", service="EC2",
                        resource_id=inst['InstanceId'], region=region, account_id=account_id,
                        issue=f"IMDSv1 enabled ({inst['InstanceType']})",
                        severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                        risk="SSRF attacks can steal instance credentials",
                    ))
    except Exception as _exc:
        handle_check_error(_exc)
    return findings


@register_check(check_id="aws-ec2-011", service="EC2", provider="aws", finding_type=FindingType.SECURITY, description="Find instances with unencrypted EBS volumes")
def check_unencrypted_ebs(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag instances with at least one unencrypted attached volume."""
    ec2 = session.client('ec2', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        instances = ec2.describe_instances()
        for res in instances['Reservations']:
            for inst in res['Instances']:
                if excluded_by_tags(inst, kwargs):
                    continue
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
                        except Exception as _exc:
                            handle_check_error(_exc)
                            continue
    except Exception as _exc:
        handle_check_error(_exc)
    return findings


@register_check(check_id="aws-ec2-012", service="EC2", provider="aws", finding_type=FindingType.SECURITY, description="Find instances with no recent AMI backup")
def check_no_recent_backup(session: 'boto3.Session', region: str, days=30, **kwargs) -> List[Finding]:
    """Flag instances without a recent AMI — no recovery point available."""
    ec2 = session.client('ec2', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        cutoff = datetime.now() - timedelta(days=days)
        # Fetch all account AMIs once, build a set of source instance IDs
        images = ec2.describe_images(Owners=[account_id])
        recent_instance_ids = set()
        for img in images['Images']:
            try:
                created = datetime.strptime(img['CreationDate'], '%Y-%m-%dT%H:%M:%S.%fZ')
            except ValueError:
                created = datetime.strptime(img['CreationDate'], '%Y-%m-%dT%H:%M:%SZ')
            if created > cutoff:
                # Tag 'SourceInstanceId' is set by create-image; also check Name tag
                for tag in img.get('Tags', []):
                    if tag['Key'] == 'SourceInstanceId':
                        recent_instance_ids.add(tag['Value'])
                # Also check image name pattern i-xxxxxxxxxxxxxxxxx
                name = img.get('Name', '')
                if name.startswith('i-') and len(name.split('-')) >= 2:
                    recent_instance_ids.add(name.split()[0])
        instances = ec2.describe_instances()
        for res in instances['Reservations']:
            for inst in res['Instances']:
                if excluded_by_tags(inst, kwargs):
                    continue
                if inst['InstanceId'] not in recent_instance_ids:
                    findings.append(Finding(
                        check_id="aws-ec2-012", service="EC2",
                        resource_id=inst['InstanceId'], region=region, account_id=account_id,
                        issue=f"No AMI backup in {days}+ days",
                        severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                        risk="No recovery point available",
                    ))
    except Exception as _exc:
        handle_check_error(_exc)
    return findings


@register_check(check_id="aws-ec2-013", service="EC2", provider="aws", finding_type=FindingType.SECURITY, description="Find instances that are both IMDSv1 and oversized")
def check_imdsv1_oversized(session: 'boto3.Session', region: str, days=14, cpu_threshold=20, **kwargs) -> List[Finding]:
    """Cross-reference: SSRF-vulnerable AND wasting money — highest remediation priority."""
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
                if excluded_by_tags(inst, kwargs):
                    continue
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
                except Exception as _exc:
                    handle_check_error(_exc)
                    continue
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
