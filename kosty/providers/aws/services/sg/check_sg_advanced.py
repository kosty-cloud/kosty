from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(check_id="aws-sg-004", service="SG", provider="aws", finding_type=FindingType.SECURITY, description="Find SGs with database ports open to 0.0.0.0/0")
def check_database_ports_open(session, region, **kwargs):
    """Flag SGs exposing MySQL, PostgreSQL, MSSQL, MongoDB to the internet."""
    ec2 = session.client('ec2', region_name=region)
    account_id = get_account_id(session)
    findings = []
    db_ports = [3306, 5432, 1433, 27017]
    try:
        for sg in ec2.describe_security_groups()['SecurityGroups']:
            for rule in sg.get('IpPermissions', []):
                from_port = rule.get('FromPort', 0)
                to_port = rule.get('ToPort', 0)
                if any(from_port <= p <= to_port for p in db_ports):
                    if any(ip.get('CidrIp') == '0.0.0.0/0' for ip in rule.get('IpRanges', [])):
                        findings.append(Finding(
                            check_id="aws-sg-004", service="SG",
                            resource_id=sg['GroupId'], region=region, account_id=account_id,
                            issue=f"Database ports open to 0.0.0.0/0 (ports {from_port}-{to_port})",
                            severity=Severity.CRITICAL, finding_type=FindingType.SECURITY,
                            risk="Direct database access from the internet",
                            resource_name=sg.get('GroupName', ''),
                        ))
                        break
    except Exception:
        pass
    return findings


@register_check(check_id="aws-sg-005", service="SG", provider="aws", finding_type=FindingType.SECURITY, description="Find SGs with wide CIDR rules (>=/16)")
def check_wide_cidr_rules(session, region, **kwargs):
    """Flag overly permissive CIDR ranges granting access to huge IP blocks."""
    ec2 = session.client('ec2', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        for sg in ec2.describe_security_groups()['SecurityGroups']:
            for rule in sg.get('IpPermissions', []):
                for ip_range in rule.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp', '')
                    if '/' in cidr:
                        prefix = int(cidr.split('/')[1])
                        if prefix <= 16 and cidr != '0.0.0.0/0':
                            findings.append(Finding(
                                check_id="aws-sg-005", service="SG",
                                resource_id=sg['GroupId'], region=region, account_id=account_id,
                                issue=f"Wide CIDR rule: {cidr} (/{prefix})",
                                severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                                risk="65K+ IPs can reach this resource",
                                resource_name=sg.get('GroupName', ''),
                            ))
                            break
    except Exception:
        pass
    return findings


@register_check(check_id="aws-sg-006", service="SG", provider="aws", finding_type=FindingType.SECURITY, description="Find overly complex security groups (50+ rules)")
def check_complex_security_groups(session, region, rule_threshold=50, **kwargs):
    """Flag SGs with too many rules — hard to audit and likely misconfigured."""
    ec2 = session.client('ec2', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        for sg in ec2.describe_security_groups()['SecurityGroups']:
            total_rules = len(sg.get('IpPermissions', [])) + len(sg.get('IpPermissionsEgress', []))
            if total_rules >= rule_threshold:
                findings.append(Finding(
                    check_id="aws-sg-006", service="SG",
                    resource_id=sg['GroupId'], region=region, account_id=account_id,
                    issue=f"Complex SG with {total_rules} rules",
                    severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                    risk="Difficult to audit — likely contains stale or conflicting rules",
                    resource_name=sg.get('GroupName', ''),
                ))
    except Exception:
        pass
    return findings
