from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.core.tag_utils import excluded_by_tags
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-nat-002", service="NAT", provider="aws", finding_type=FindingType.COST, description="Find redundant NAT Gateways in same AZ")
def check_redundant_nat_gateways(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag multiple NAT Gateways in the same subnet — one is enough per AZ."""
    ec2 = session.client('ec2', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        gateways = ec2.describe_nat_gateways(Filters=[{'Name': 'state', 'Values': ['available']}])['NatGateways']
        subnet_count = {}
        for gw in gateways:
            if excluded_by_tags(gw, kwargs):
                continue
            subnet = gw.get('SubnetId', '')
            subnet_count[subnet] = subnet_count.get(subnet, 0) + 1

        for subnet, count in subnet_count.items():
            if count > 1:
                findings.append(Finding(
                    check_id="aws-nat-002", service="NAT",
                    resource_id=subnet, region=region, account_id=account_id,
                    issue=f"{count} NAT Gateways in same subnet {subnet}",
                    severity=Severity.MEDIUM, finding_type=FindingType.COST,
                    risk=f"${(count - 1) * 32.85:.2f}/mo wasted on redundant gateways",
                    monthly_savings=(count - 1) * 32.85,
                ))
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
