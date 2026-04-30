from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id


@register_check(check_id="aws-apigateway-002", service="APIGateway", provider="aws", finding_type=FindingType.SECURITY, description="Find stages not protected by WAF")
def check_no_waf(session, region, **kwargs):
    """Flag API stages exposed without WAF protection."""
    apigw = session.client('apigateway', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        for api in apigw.get_rest_apis().get('items', []):
            try:
                for stage in apigw.get_stages(restApiId=api['id']).get('item', []):
                    if not stage.get('webAclArn', ''):
                        findings.append(Finding(
                            check_id="aws-apigateway-002", service="APIGateway",
                            resource_id=f"{api['name']}/{stage['stageName']}",
                            region=region, account_id=account_id,
                            issue="Stage not protected by WAF",
                            severity=Severity.HIGH, finding_type=FindingType.SECURITY,
                            risk="No protection against OWASP Top 10",
                        ))
            except Exception:
                continue
    except Exception:
        pass
    return findings
