from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity
from kosty.providers.aws.session_utils import get_account_id
from kosty.providers.aws.error_utils import handle_check_error
from typing import List


@register_check(check_id="aws-apigateway-009", service="APIGateway", provider="aws", finding_type=FindingType.SECURITY, description="Find methods without request validation")
def check_missing_request_validation(session: 'boto3.Session', region: str, **kwargs) -> List[Finding]:
    """Flag APIs accepting unvalidated payloads from clients."""
    apigw = session.client('apigateway', region_name=region)
    account_id = get_account_id(session)
    findings = []
    try:
        for api in apigw.get_rest_apis().get('items', []):
            try:
                validators = apigw.get_request_validators(restApiId=api['id'])
                if not validators.get('items', []):
                    findings.append(Finding(
                        check_id="aws-apigateway-009", service="APIGateway",
                        resource_id=api['name'], region=region, account_id=account_id,
                        issue="No request validators defined",
                        severity=Severity.MEDIUM, finding_type=FindingType.SECURITY,
                        risk="Malformed requests reach backend without validation",
                    ))
            except Exception as _exc:
                handle_check_error(_exc)
                continue
    except Exception as _exc:
        handle_check_error(_exc)
    return findings
