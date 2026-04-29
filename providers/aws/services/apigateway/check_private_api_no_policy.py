from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(check_id="aws-apigateway-006", service="APIGateway", provider="aws", finding_type=FindingType.SECURITY, description="Find private APIs without resource policy")
def check_private_api_no_policy(session, region, **kwargs):
    """Flag private APIs accessible from any VPC endpoint without restriction."""
    apigw = session.client('apigateway', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        for api in apigw.get_rest_apis().get('items', []):
            types = api.get('endpointConfiguration', {}).get('types', [])
            if 'PRIVATE' not in types:
                continue
            if not api.get('policy', ''):
                findings.append(Finding(
                    check_id="aws-apigateway-006", service="APIGateway",
                    resource_id=api['name'], region=region, account_id=account_id,
                    issue="Private API has no resource policy",
                    severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                    risk="Accessible from any VPC endpoint without restriction",
                ))
    except Exception:
        pass
    return findings
