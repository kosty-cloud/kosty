from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(check_id="aws-rds-011", service="RDS", provider="aws", finding_type=FindingType.SECURITY, description="Find wide CIDR in RDS security groups")
def check_wide_cidr_sg(session, region, **kwargs):
    """Flag databases accessible from overly broad IP ranges."""
    rds = session.client('rds', region_name=region)
    ec2 = session.client('ec2', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        for db in rds.describe_db_instances()['DBInstances']:
            for sg in db.get('VpcSecurityGroups', []):
                try:
                    detail = ec2.describe_security_groups(GroupIds=[sg['VpcSecurityGroupId']])['SecurityGroups'][0]
                    for rule in detail.get('IpPermissions', []):
                        for ip in rule.get('IpRanges', []):
                            cidr = ip.get('CidrIp', '')
                            if '/' in cidr and int(cidr.split('/')[1]) <= 16:
                                findings.append(Finding(
                                    check_id="aws-rds-011", service="RDS",
                                    resource_id=db['DBInstanceIdentifier'], region=region, account_id=account_id,
                                    issue=f"SG allows {cidr}", severity=Severity.HIGH,
                                    finding_type=FindingType.SECURITY, risk="Overly permissive network access", arn=db['DBInstanceArn'],
                                ))
                                break
                except Exception:
                    continue
    except Exception:
        pass
    return findings
