from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(
    check_id="aws-vpc-002",
    service="VPC",
    provider="aws",
    finding_type=FindingType.SECURITY,
    description="Find default security groups with inbound rules",
)
def check_default_sg_open(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag default SGs that allow inbound traffic."""
    ec2 = session.client('ec2', region_name=region)
    account_id = get_account_id(session)
    findings = []

    try:
        sgs = ec2.describe_security_groups(Filters=[{'Name': 'group-name', 'Values': ['default']}])
        for sg in sgs['SecurityGroups']:
            if sg.get('IpPermissions'):
                findings.append(Finding(
                    check_id="aws-vpc-002", service="VPC",
                    resource_id=sg['GroupId'], resource_name=f"default ({sg['VpcId']})",
                    region=region, account_id=account_id,
                    issue="Default security group has inbound rules",
                    severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                    risk="Resources added to VPC inherit these permissive rules by default",
                ))
    except Exception as _exc:
        handle_check_error(_exc)

    return findings
