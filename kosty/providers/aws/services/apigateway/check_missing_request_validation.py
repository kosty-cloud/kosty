from kosty.core.registry import register_check
from kosty.core.models import Finding, FindingType, Severity


@register_check(check_id="aws-apigateway-009", service="APIGateway", provider="aws", finding_type=FindingType.SECURITY, description="Find methods without request validation")
def check_missing_request_validation(session, region, **kwargs):
    """Flag APIs accepting unvalidated payloads from clients."""
    apigw = session.client('apigateway', region_name=region)
    account_id = session.client('sts').get_caller_identity()['Account']
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
            except Exception:
                continue
    except Exception:
        pass
    return findings
