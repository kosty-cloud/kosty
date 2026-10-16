from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.core.tag_utils import excluded_by_tags
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(
    check_id="aws-eip-001",
    service="EIP",
    provider="aws",
    finding_type=FindingType.COST,
    description="Find Elastic IPs not attached to any instance",
)
def check_unattached_eips(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag EIPs billing $3.60/mo with no associated resource."""
    ec2 = session.client('ec2', region_name=region)
    account_id = get_account_id(session)
    findings = []

    try:
        for addr in ec2.describe_addresses().get('Addresses', []):
            if excluded_by_tags(addr, kwargs):
                continue
            if not addr.get('AssociationId'):
                findings.append(Finding(
                    check_id="aws-eip-001", service="EIP",
                    resource_id=addr.get('AllocationId', addr.get('PublicIp', '')),
                    region=region, account_id=account_id,
                    issue=f"Unattached EIP ({addr.get('PublicIp', '')})",
                    severity=Severity.MEDIUM, finding_type=FindingType.COST,
                    risk="$3.60/mo per unattached EIP",
                    monthly_savings=3.60,
                ))
    except Exception as _exc:
        handle_check_error(_exc)

    return findings
