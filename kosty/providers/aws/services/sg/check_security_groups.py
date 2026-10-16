from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.core.tag_utils import excluded_by_tags
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-sg-001", service="SG", provider="aws", finding_type=FindingType.SECURITY, description="Find security groups with SSH/RDP open to 0.0.0.0/0")
def check_ssh_rdp_open(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag SGs allowing admin port access from the internet."""
    ec2 = session.client('ec2', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        for sg in ec2.describe_security_groups()['SecurityGroups']:
            if excluded_by_tags(sg, kwargs):
                continue
            for rule in sg.get('IpPermissions', []):
                from_port = rule.get('FromPort', 0)
                to_port = rule.get('ToPort', 0)
                if from_port in [22, 3389] or to_port in [22, 3389]:
                    if any(ip.get('CidrIp') == '0.0.0.0/0' for ip in rule.get('IpRanges', [])):
                        port = 22 if from_port == 22 or to_port == 22 else 3389
                        findings.append(Finding(
                            check_id="aws-sg-001", service="SG",
                            resource_id=sg['GroupId'], region=region, account_id=account_id,
                            issue=f"Port {port} open to 0.0.0.0/0",
                            severity=Severity.CRITICAL, finding_type=FindingType.SECURITY,
                            risk="Brute force attacks from the internet",
                            resource_name=sg.get('GroupName', ''),
                        ))
                        break
    except Exception as _exc:
        handle_check_error(_exc)
    return findings


@register_check(check_id="aws-sg-002", service="SG", provider="aws", finding_type=FindingType.SECURITY, description="Find security groups with all ports open to 0.0.0.0/0")
def check_all_ports_open(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag SGs with unrestricted inbound access."""
    ec2 = session.client('ec2', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        for sg in ec2.describe_security_groups()['SecurityGroups']:
            if excluded_by_tags(sg, kwargs):
                continue
            for rule in sg.get('IpPermissions', []):
                if rule.get('IpProtocol') == '-1':
                    if any(ip.get('CidrIp') == '0.0.0.0/0' for ip in rule.get('IpRanges', [])):
                        findings.append(Finding(
                            check_id="aws-sg-002", service="SG",
                            resource_id=sg['GroupId'], region=region, account_id=account_id,
                            issue="All traffic open to 0.0.0.0/0",
                            severity=Severity.CRITICAL, finding_type=FindingType.SECURITY,
                            risk="Entire instance exposed to the internet",
                            resource_name=sg.get('GroupName', ''),
                        ))
                        break
    except Exception as _exc:
        handle_check_error(_exc)
    return findings


@register_check(check_id="aws-sg-003", service="SG", provider="aws", finding_type=FindingType.COST, description="Find security groups not attached to any resource")
def check_unused_security_groups(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag orphaned SGs adding clutter and confusion."""
    ec2 = session.client('ec2', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        all_sgs = {sg['GroupId'] for sg in ec2.describe_security_groups()['SecurityGroups']}
        used_sgs = set()
        for eni in ec2.describe_network_interfaces()['NetworkInterfaces']:
            for sg in eni.get('Groups', []):
                used_sgs.add(sg['GroupId'])
        for sg_id in all_sgs - used_sgs:
            sg_detail = ec2.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
            if excluded_by_tags(sg_detail, kwargs):
                continue
            if sg_detail['GroupName'] == 'default':
                continue
            findings.append(Finding(
                check_id="aws-sg-003", service="SG",
                resource_id=sg_id, region=region, account_id=account_id,
                issue="Security group not attached to any ENI",
                severity=Severity.LOW, finding_type=FindingType.COST,
                risk="Orphaned SG — adds confusion during audits",
                resource_name=sg_detail.get('GroupName', ''),
            ))
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
