from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.core.tag_utils import excluded_by_tags
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-ec2-005", service="EC2", provider="aws", finding_type=FindingType.SECURITY, description="Find instances with SSH open to 0.0.0.0/0")
def check_ssh_open(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag instances reachable on port 22 from the entire internet."""
    ec2 = session.client('ec2', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        sgs = ec2.describe_security_groups()
        ssh_sgs = set()
        for sg in sgs['SecurityGroups']:
            for rule in sg.get('IpPermissions', []):
                if rule.get('FromPort') == 22 and rule.get('ToPort') == 22:
                    if any(ip.get('CidrIp') == '0.0.0.0/0' for ip in rule.get('IpRanges', [])):
                        ssh_sgs.add(sg['GroupId'])

        instances = ec2.describe_instances()
        for res in instances['Reservations']:
            for inst in res['Instances']:
                if excluded_by_tags(inst, kwargs):
                    continue
                inst_sgs = {sg['GroupId'] for sg in inst.get('SecurityGroups', [])}
                if inst_sgs & ssh_sgs:
                    findings.append(Finding(
                        check_id="aws-ec2-005", service="EC2",
                        resource_id=inst['InstanceId'], region=region, account_id=account_id,
                        issue="SSH port 22 open to 0.0.0.0/0",
                        severity=Severity.CRITICAL, finding_type=FindingType.SECURITY,
                        risk="Brute force attacks (38k/day avg)",
                    ))
    except Exception as _exc:
        handle_check_error(_exc)
    return findings


@register_check(check_id="aws-ec2-006", service="EC2", provider="aws", finding_type=FindingType.SECURITY, description="Find instances with RDP open to 0.0.0.0/0")
def check_rdp_open(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag instances reachable on port 3389 from the entire internet."""
    ec2 = session.client('ec2', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        sgs = ec2.describe_security_groups()
        rdp_sgs = set()
        for sg in sgs['SecurityGroups']:
            for rule in sg.get('IpPermissions', []):
                if rule.get('FromPort') == 3389 and rule.get('ToPort') == 3389:
                    if any(ip.get('CidrIp') == '0.0.0.0/0' for ip in rule.get('IpRanges', [])):
                        rdp_sgs.add(sg['GroupId'])

        instances = ec2.describe_instances()
        for res in instances['Reservations']:
            for inst in res['Instances']:
                if excluded_by_tags(inst, kwargs):
                    continue
                inst_sgs = {sg['GroupId'] for sg in inst.get('SecurityGroups', [])}
                if inst_sgs & rdp_sgs:
                    findings.append(Finding(
                        check_id="aws-ec2-006", service="EC2",
                        resource_id=inst['InstanceId'], region=region, account_id=account_id,
                        issue="RDP port 3389 open to 0.0.0.0/0",
                        severity=Severity.CRITICAL, finding_type=FindingType.SECURITY,
                        risk="Brute force and ransomware vector",
                    ))
    except Exception as _exc:
        handle_check_error(_exc)
    return findings


@register_check(check_id="aws-ec2-007", service="EC2", provider="aws", finding_type=FindingType.SECURITY, description="Find instances with database ports open to internet")
def check_database_ports_open(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag instances exposing MySQL/PostgreSQL/MSSQL/MongoDB to the world."""
    ec2 = session.client('ec2', region_name=region)
    account_id = get_account_id(session)
    findings = []
    db_ports = [3306, 5432, 1433, 27017]
    try:
        sgs = ec2.describe_security_groups()
        db_sgs = set()
        for sg in sgs['SecurityGroups']:
            for rule in sg.get('IpPermissions', []):
                fp, tp = rule.get('FromPort', 0), rule.get('ToPort', 0)
                if any(fp <= p <= tp for p in db_ports):
                    if any(ip.get('CidrIp') == '0.0.0.0/0' for ip in rule.get('IpRanges', [])):
                        db_sgs.add(sg['GroupId'])

        instances = ec2.describe_instances()
        for res in instances['Reservations']:
            for inst in res['Instances']:
                if excluded_by_tags(inst, kwargs):
                    continue
                inst_sgs = {sg['GroupId'] for sg in inst.get('SecurityGroups', [])}
                if inst_sgs & db_sgs:
                    findings.append(Finding(
                        check_id="aws-ec2-007", service="EC2",
                        resource_id=inst['InstanceId'], region=region, account_id=account_id,
                        issue="Database ports open to 0.0.0.0/0",
                        severity=Severity.CRITICAL, finding_type=FindingType.SECURITY,
                        risk="Unauthorized database access from internet",
                    ))
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
