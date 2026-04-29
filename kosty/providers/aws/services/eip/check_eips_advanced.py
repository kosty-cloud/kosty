from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(check_id="aws-eip-002", service="EIP", provider="aws", finding_type=FindingType.COST, description="Find EIPs attached to stopped instances")
def check_eips_on_stopped_instances(session, region, **kwargs):
    """Flag EIPs billing on instances that aren't running."""
    ec2 = session.client('ec2', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        for addr in ec2.describe_addresses().get('Addresses', []):
            instance_id = addr.get('InstanceId')
            if not instance_id:
                continue
            try:
                instances = ec2.describe_instances(InstanceIds=[instance_id])
                for res in instances['Reservations']:
                    for inst in res['Instances']:
                        if inst['State']['Name'] != 'running':
                            findings.append(Finding(
                                check_id="aws-eip-002", service="EIP",
                                resource_id=addr.get('AllocationId', addr.get('PublicIp', '')),
                                region=region, account_id=account_id,
                                issue=f"EIP on stopped instance {instance_id}",
                                severity=Severity.MEDIUM, finding_type=FindingType.COST,
                                risk="$3.60/mo — EIP billed when instance is stopped",
                                monthly_savings=3.60,
                            ))
            except Exception:
                continue
    except Exception:
        pass
    return findings


@register_check(check_id="aws-eip-003", service="EIP", provider="aws", finding_type=FindingType.SECURITY, description="Find EIPs on instances with dangerous SG rules")
def check_eips_with_dangerous_sg(session, region, **kwargs):
    """Flag public IPs on instances with SSH/RDP open to the world."""
    ec2 = session.client('ec2', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        for addr in ec2.describe_addresses().get('Addresses', []):
            instance_id = addr.get('InstanceId')
            if not instance_id:
                continue
            try:
                instances = ec2.describe_instances(InstanceIds=[instance_id])
                for res in instances['Reservations']:
                    for inst in res['Instances']:
                        for sg in inst.get('SecurityGroups', []):
                            sg_detail = ec2.describe_security_groups(GroupIds=[sg['GroupId']])['SecurityGroups'][0]
                            for rule in sg_detail.get('IpPermissions', []):
                                port = rule.get('FromPort', 0)
                                if port in [22, 3389] and any(ip.get('CidrIp') == '0.0.0.0/0' for ip in rule.get('IpRanges', [])):
                                    findings.append(Finding(
                                        check_id="aws-eip-003", service="EIP",
                                        resource_id=addr.get('PublicIp', ''),
                                        region=region, account_id=account_id,
                                        issue=f"EIP {addr.get('PublicIp')} on instance with port {port} open to internet",
                                        severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                                        risk="Public IP + open admin port = brute force target",
                                    ))
                                    break
            except Exception:
                continue
    except Exception:
        pass
    return findings
