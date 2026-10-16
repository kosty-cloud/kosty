from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-apigateway-006", service="APIGateway", provider="aws", finding_type=FindingType.SECURITY, description="Find private APIs without resource policy")
def check_private_api_no_policy(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag private APIs accessible from any VPC endpoint without restriction."""
    apigw = session.client('apigateway', region_name=region)
    account_id = get_account_id(session)
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
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
