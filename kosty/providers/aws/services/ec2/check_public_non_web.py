from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(check_id="aws-ec2-008", service="EC2", provider="aws", finding_type=FindingType.SECURITY, description="Find public IPs on non-web instances")
def check_public_non_web(session, region, **kwargs):
    """Flag instances with public IPs that don't serve web traffic — unnecessary exposure."""
    ec2 = session.client('ec2', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    web_ports = {80, 443, 8080, 8443}
    try:
        instances = ec2.describe_instances()
        for res in instances['Reservations']:
            for inst in res['Instances']:
                if not inst.get('PublicIpAddress'):
                    continue
                has_web = False
                for sg in inst.get('SecurityGroups', []):
                    try:
                        detail = ec2.describe_security_groups(GroupIds=[sg['GroupId']])['SecurityGroups'][0]
                        for rule in detail.get('IpPermissions', []):
                            fp, tp = rule.get('FromPort', 0), rule.get('ToPort', 0)
                            if any(fp <= p <= tp for p in web_ports):
                                has_web = True
                                break
                    except Exception:
                        continue
                    if has_web:
                        break
                if not has_web:
                    findings.append(Finding(
                        check_id="aws-ec2-008", service="EC2",
                        resource_id=inst['InstanceId'], region=region, account_id=account_id,
                        issue=f"Public IP ({inst['PublicIpAddress']}) on non-web instance",
                        severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                        risk="Unnecessary attack surface",
                    ))
    except Exception:
        pass
    return findings
