from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(check_id="aws-apigateway-005", service="APIGateway", provider="aws", finding_type=FindingType.SECURITY, description="Find stages without custom throttling")
def check_no_throttling(session, region, **kwargs):
    """Flag stages using AWS defaults — vulnerable to cost-bleeding attacks."""
    apigw = session.client('apigateway', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        for api in apigw.get_rest_apis().get('items', []):
            try:
                for stage in apigw.get_stages(restApiId=api['id']).get('item', []):
                    settings = stage.get('methodSettings', {}).get('*/*', {})
                    rate = settings.get('throttlingRateLimit', 0)
                    if rate == 0 or rate >= 10000:
                        findings.append(Finding(
                            check_id="aws-apigateway-005", service="APIGateway",
                            resource_id=f"{api['name']}/{stage['stageName']}",
                            region=region, account_id=account_id,
                            issue="No custom throttling configured",
                            severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                            risk="Cost-bleeding attack via unrestricted invocations",
                        ))
            except Exception:
                continue
    except Exception:
        pass
    return findings
