from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(
    check_id="aws-vpc-001",
    service="VPC",
    provider="aws",
    finding_type=FindingType.SECURITY,
    description="Find VPCs without Flow Logs enabled",
)
def check_no_flow_logs(session, region, **kwargs):
    """Flag VPCs with no network traffic visibility."""
    ec2 = session.client('ec2', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []

    try:
        vpcs = ec2.describe_vpcs()['Vpcs']
        flow_logs = ec2.describe_flow_logs()['FlowLogs']
        logged = {fl['ResourceId'] for fl in flow_logs if fl.get('ResourceId', '').startswith('vpc-')}

        for vpc in vpcs:
            if vpc['VpcId'] not in logged:
                name = next((t['Value'] for t in vpc.get('Tags', []) if t['Key'] == 'Name'), vpc['VpcId'])
                findings.append(Finding(
                    check_id="aws-vpc-001", service="VPC",
                    resource_id=vpc['VpcId'], resource_name=name,
                    region=region, account_id=account_id,
                    issue="VPC Flow Logs not enabled",
                    severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                    risk="No network traffic visibility — blind to lateral movement",
                ))
    except Exception:
        pass

    return findings
