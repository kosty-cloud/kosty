from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-apigateway-004", service="APIGateway", provider="aws", finding_type=FindingType.SECURITY, description="Find stages with logging disabled")
def check_no_logging(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag stages without access or execution logging."""
    apigw = session.client('apigateway', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        for api in apigw.get_rest_apis().get('items', []):
            try:
                for stage in apigw.get_stages(restApiId=api['id']).get('item', []):
                    issues = []
                    if not stage.get('accessLogSettings', {}).get('destinationArn'):
                        issues.append('Access logging disabled')
                    settings = stage.get('methodSettings', {}).get('*/*', {})
                    if not settings.get('loggingLevel') or settings.get('loggingLevel') == 'OFF':
                        issues.append('Execution logging disabled')
                    if issues:
                        findings.append(Finding(
                            check_id="aws-apigateway-004", service="APIGateway",
                            resource_id=f"{api['name']}/{stage['stageName']}",
                            region=region, account_id=account_id,
                            issue=f"{', '.join(issues)}",
                            severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                            risk="No audit trail for API requests",
                        ))
            except Exception as _exc:
                handle_check_error(_exc)
                continue
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
