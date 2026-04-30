from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(check_id="aws-bedrock-005", service="Bedrock", provider="aws", finding_type=FindingType.SECURITY, description="Check if VPC endpoint exists for Bedrock runtime")
def check_no_vpc_endpoint(session, region, **kwargs):
    """Flag accounts where model invocations traverse the public internet."""
    ec2 = session.client('ec2', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        eps = ec2.describe_vpc_endpoints(Filters=[{'Name': 'service-name', 'Values': [f'com.amazonaws.{region}.bedrock-runtime']}])
        if not eps.get('VpcEndpoints', []):
            findings.append(Finding(
                check_id="aws-bedrock-005", service="Bedrock",
                resource_id="bedrock-vpc-endpoint", region=region, account_id=account_id,
                issue="No VPC endpoint for Bedrock runtime",
                severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                risk="Model invocations traverse the public internet",
            ))
    except Exception:
        pass
    return findings
