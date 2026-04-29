from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(
    check_id="aws-eip-001",
    service="EIP",
    provider="aws",
    finding_type=FindingType.COST,
    description="Find Elastic IPs not attached to any instance",
)
def check_unattached_eips(session, region, **kwargs):
    """Flag EIPs billing $3.60/mo with no associated resource."""
    ec2 = session.client('ec2', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []

    try:
        for addr in ec2.describe_addresses().get('Addresses', []):
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
    except Exception:
        pass

    return findings
