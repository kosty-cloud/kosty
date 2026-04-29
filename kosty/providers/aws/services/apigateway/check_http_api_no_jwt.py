from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(check_id="aws-apigateway-007", service="APIGateway", provider="aws", finding_type=FindingType.SECURITY, description="Find HTTP APIs without JWT authorizer")
def check_http_api_no_jwt(session, region, **kwargs):
    """Flag HTTP APIs (v2) with no token-based auth configured."""
    apigwv2 = session.client('apigatewayv2', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
    findings = []
    try:
        for api in apigwv2.get_apis().get('Items', []):
            if api.get('ProtocolType') != 'HTTP':
                continue
            try:
                authorizers = apigwv2.get_authorizers(ApiId=api['ApiId'])
                has_jwt = any(a.get('AuthorizerType') == 'JWT' for a in authorizers.get('Items', []))
                if not has_jwt:
                    findings.append(Finding(
                        check_id="aws-apigateway-007", service="APIGateway",
                        resource_id=api.get('Name', api['ApiId']),
                        region=region, account_id=account_id,
                        issue="HTTP API has no JWT authorizer",
                        severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                        risk="No token-based authentication on routes",
                    ))
            except Exception:
                continue
    except Exception:
        pass
    return findings
